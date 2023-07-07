use std::collections::{HashMap, VecDeque};
use std::ops::Deref;
use std::sync::Mutex;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hash_types::{BlockHash, Txid};

use lightning::chain;
use lightning::chain::chaininterface::FEERATE_FLOOR_SATS_PER_KW;
use lightning::chain::chainmonitor::{self, MonitorUpdateId};
use lightning::chain::channelmonitor::{self, ChannelMonitor, RevokeableOutputData};
use lightning::chain::transaction::OutPoint;
use lightning::sign::{self, EntropySource, SignerProvider};
use lightning::util::persist::KVStorePersister;
use lightning::util::ser::Writeable;
use lightning_persister::FilesystemPersister;

// number_of_witness_elements + sig_length + revocation_sig + true_length + op_true + witness_script_length + witness_script
pub(crate) const WEIGHT_REVOKED_OUTPUT: u64 = 1 + 1 + 73 + 1 + 1 + 1 + 77;

pub(crate) struct WatchtowerPersister {
	persister: FilesystemPersister,
	/// Upon a new commitment signed, we'll get a
	/// ChannelMonitorUpdateStep::LatestCounterpartyCommitmentTxInfo. We'll store the commitment txid
	/// and revokeable output index and value to use to form the justice tx once we get a
	/// revoke_and_ack with the commitment secret.
	revokeable_output_data: Mutex<HashMap<OutPoint, VecDeque<RevokeableOutputData>>>,
	/// After receiving a revoke_and_ack for a commitment number, we'll form and store the justice
	/// tx which would be used to provide a watchtower with the data it needs.
	watchtower_state: Mutex<HashMap<OutPoint, HashMap<Txid, Transaction>>>,
}

impl WatchtowerPersister {
	pub(crate) fn new(path_to_channel_data: String) -> Self {
		WatchtowerPersister {
			persister: FilesystemPersister::new(path_to_channel_data),
			revokeable_output_data: Mutex::new(HashMap::new()),
			watchtower_state: Mutex::new(HashMap::new()),
		}
	}

	pub(crate) fn justice_tx(
		&self, funding_txo: OutPoint, commitment_txid: &Txid,
	) -> Option<Transaction> {
		self.watchtower_state
			.lock()
			.unwrap()
			.get(&funding_txo)
			.unwrap()
			.get(commitment_txid)
			.cloned()
	}

	pub fn persist<W: Writeable>(&self, key: &str, object: &W) -> std::io::Result<()> {
		self.persister.persist(key, object)
	}

	pub fn read_channelmonitors<ES: Deref, SP: Deref>(
		&self, entropy_source: ES, signer_provider: SP,
	) -> std::io::Result<Vec<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::Signer>)>>
	where
		ES::Target: EntropySource + Sized,
		SP::Target: SignerProvider + Sized,
	{
		self.persister.read_channelmonitors(entropy_source, signer_provider)
	}
}

impl<Signer: sign::WriteableEcdsaChannelSigner> chainmonitor::Persist<Signer>
	for WatchtowerPersister
{
	fn persist_new_channel(
		&self, funding_txo: OutPoint, data: &channelmonitor::ChannelMonitor<Signer>,
		id: MonitorUpdateId,
	) -> chain::ChannelMonitorUpdateStatus {
		assert!(self
			.revokeable_output_data
			.lock()
			.unwrap()
			.insert(funding_txo, VecDeque::new())
			.is_none());
		assert!(self
			.watchtower_state
			.lock()
			.unwrap()
			.insert(funding_txo, HashMap::new())
			.is_none());
		println!("Initial commitment");
		self.persister.persist_new_channel(funding_txo, data, id)
		// TODO: accomodate for first channel update
	}

	fn update_persisted_channel(
		&self, funding_txo: OutPoint, update: Option<&channelmonitor::ChannelMonitorUpdate>,
		data: &channelmonitor::ChannelMonitor<Signer>, update_id: MonitorUpdateId,
	) -> chain::ChannelMonitorUpdateStatus {
		if let Some(update) = update {
			// Track new counterparty commitment txs
			let revokeable_output_data = data.revokeable_output_data_from_update(update);
			let mut channels_revokeable_output_data = self.revokeable_output_data.lock().unwrap();
			let channel_state = channels_revokeable_output_data.get_mut(&funding_txo).unwrap();
			channel_state.extend(revokeable_output_data.into_iter());

			// Form justice txs for revoked counterparty commitment txs
			while let Some(RevokeableOutputData {
				commitment_number,
				commitment_txid,
				output_idx,
				value,
			}) = channel_state.front()
			{
				let mut justice_tx =
					data.build_justice_tx(*commitment_txid, *output_idx as u32, *value);

				// Fee estimation
				let weight = justice_tx.weight() as u64 + WEIGHT_REVOKED_OUTPUT;
				let min_feerate_per_kw = FEERATE_FLOOR_SATS_PER_KW;
				let fee = min_feerate_per_kw as u64 * weight / 1000;
				justice_tx.output[0].value -= fee;

				// Sign justice tx
				let input_idx = 0;
				match data.sign_justice_tx(justice_tx, input_idx, *value, *commitment_number) {
					Ok(signed_justice_tx) => {
						println!(
							"Channel updated ({}). commitment_txid: {}, penalty: {:?}",
							commitment_number, commitment_txid, signed_justice_tx
						);
						let dup = self
							.watchtower_state
							.lock()
							.unwrap()
							.get_mut(&funding_txo)
							.unwrap()
							.insert(*commitment_txid, signed_justice_tx);
						assert!(dup.is_none());
						channel_state.pop_front();
					}
					Err(_) => break,
				}
			}
		}
		self.persister.update_persisted_channel(funding_txo, update, data, update_id)
	}
}

// impl KVStorePersister for WatchtowerPersister {
// 	fn persist<W: Writeable>(&self, key: &str, object: &W) -> std::io::Result<()> {
// 		self.persister.persist(key, object)
// 	}
// }
