/*
Copyright 2024 The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use std::io::Write;

use tempfile::NamedTempFile;

use super::Hypervisor;
use crate::{new_error, Result};

/// Dump registers + memory regions + raw memory to a tempfile
#[cfg(crashdump)]
pub(crate) fn crashdump_to_tempfile(hv: &dyn Hypervisor) -> Result<()> {
    let mut temp_file = NamedTempFile::with_prefix("mem")?;
    let hv_details = format!("{:#x?}", hv);

    // write hypervisor details such as registers, info about mapped memory regions, etc.
    temp_file.write_all(hv_details.as_bytes())?;
    temp_file.write_all(b"================ MEMORY DUMP =================\n")?;

    // write the raw memory dump for each memory region
    for region in hv.get_memory_regions() {
        if region.host_region.start == 0 || region.host_region.is_empty() {
            continue;
        }
        // SAFETY: we got this memory region from the hypervisor so should never be invalid
        let region_slice = unsafe {
            std::slice::from_raw_parts(
                region.host_region.start as *const u8,
                region.host_region.len(),
            )
        };
        temp_file.write_all(region_slice)?;
    }
    temp_file.flush()?;

    // persist the tempfile to disk
    let persist_path = temp_file.path().with_extension("dmp");
    temp_file
        .persist(&persist_path)
        .map_err(|e| new_error!("Failed to persist crashdump file: {:?}", e))?;

    println!("Memory dumped to file: {:?}", persist_path);
    log::error!("Memory dumped to file: {:?}", persist_path);

    Ok(())
}
