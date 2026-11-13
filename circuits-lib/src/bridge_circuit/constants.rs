//! Bridge circuit build constants. SP1 program keys are in [`crate::common::programs`].
pub fn is_test_vk() -> bool {
    cfg!(feature = "use-test-vk")
}
