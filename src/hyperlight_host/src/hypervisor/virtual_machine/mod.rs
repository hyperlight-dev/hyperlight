#[cfg(kvm)]
/// Functionality to manipulate KVM-based virtual machines
pub(crate) mod kvm;
/// HyperV-on-linux functionality
#[cfg(mshv3)]
pub(crate) mod mshv;
#[cfg(target_os = "windows")]
pub(crate) mod whp;
