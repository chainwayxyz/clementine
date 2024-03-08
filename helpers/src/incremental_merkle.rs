use crate::{
    constants::{EMPTYDATA, ZEROES},
    sha256_hash, HashType,
};
// use serde::{de::DeserializeOwned, Deserialize, Serialize};

// #[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[derive(Clone, Debug)]
pub struct IncrementalMerkleTree<const DEPTH: usize>
// where
//     [HashType; DEPTH]: Serialize + DeserializeOwned + Copy,
{
    pub filled_subtrees: [HashType; DEPTH],
    pub root: HashType,
    pub index: u32,
}

impl<const DEPTH: usize> Default for IncrementalMerkleTree<DEPTH>
// where
//     [HashType; DEPTH]: Serialize + DeserializeOwned + Copy,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const DEPTH: usize> IncrementalMerkleTree<DEPTH>
// where
//     [HashType; DEPTH]: Serialize + DeserializeOwned + Copy,
{
    pub fn new() -> Self {
        Self {
            filled_subtrees: [EMPTYDATA; DEPTH],
            root: ZEROES[DEPTH],
            index: 0,
        }
    }

    pub fn add(&mut self, a: HashType) {
        let mut current_index = self.index;
        let mut current_level_hash = a;

        for i in 0..DEPTH {
            let (left, right) = if current_index % 2 == 0 {
                self.filled_subtrees[i] = current_level_hash;
                (current_level_hash, ZEROES[i])
            } else {
                (self.filled_subtrees[i], current_level_hash)
            };
            current_level_hash = sha256_hash!(left, right);
            current_index /= 2;
        }
        self.root = current_level_hash;
        self.index += 1;
    }
}

// cargo test --package circuit-helpers --lib -- merkle::tests::test_incremental_merkle --nocapture
#[cfg(test)]
mod tests {
    use crate::incremental_merkle::IncrementalMerkleTree;

    #[test]
    fn test_incremental_merkle() {
        let mut imt = IncrementalMerkleTree::<3>::new();
        assert_eq!(
            imt.root,
            [
                199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165,
                66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60
            ]
        );
        imt.add([1_u8; 32]);
        assert_eq!(
            imt.root,
            [
                24, 22, 194, 71, 205, 34, 88, 34, 252, 151, 148, 69, 77, 235, 185, 240, 213, 87,
                192, 202, 18, 7, 177, 49, 159, 223, 112, 253, 35, 18, 193, 52
            ]
        );
    }
}
