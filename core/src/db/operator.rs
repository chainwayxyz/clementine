use super::common::Database;
use crate::{config::BridgeConfig, operator::OperatorClaimSigs, PreimageTree};
use clementine_circuits::PreimageType;
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone)]
pub struct OperatorMockDB {
    common_db: Database,
    deposit_take_sigs: Vec<OperatorClaimSigs>,
    connector_tree_preimages: Vec<PreimageTree>,
}

impl OperatorMockDB {
    pub async fn new(config: BridgeConfig) -> Self {
        Self {
            common_db: Database::new(config).await.unwrap(),
            deposit_take_sigs: Vec::new(),
            connector_tree_preimages: Vec::new(),
        }
    }
}

impl Deref for OperatorMockDB {
    type Target = Database;

    fn deref(&self) -> &Self::Target {
        &self.common_db
    }
}

impl DerefMut for OperatorMockDB {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common_db
    }
}

impl OperatorMockDB {
    // pub fn get_deposit_index(&self) -> usize {
    //     self.deposit_take_sigs.len()
    // }

    // pub fn add_deposit_take_sigs(&mut self, deposit_take_sigs: OperatorClaimSigs) {
    //     self.deposit_take_sigs.push(deposit_take_sigs);
    // }

    // pub fn get_connector_tree_preimages_level(
    //     &self,
    //     period: usize,
    //     level: usize,
    // ) -> Vec<PreimageType> {
    //     self.connector_tree_preimages[period][level].clone()
    // }

    // pub fn get_connector_tree_preimages(
    //     &self,
    //     period: usize,
    //     level: usize,
    //     idx: usize,
    // ) -> PreimageType {
    //     self.connector_tree_preimages[period][level][idx].clone()
    // }

    // pub fn set_connector_tree_preimages(
    //     &mut self,
    //     connector_tree_preimages: Vec<Vec<Vec<PreimageType>>>,
    // ) {
    //     self.connector_tree_preimages = connector_tree_preimages;
    // }
}
