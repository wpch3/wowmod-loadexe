// Arctium-style loose-file mapping preparation.
// This module only builds the deterministic FileDataID -> local-path input table; it does not
// launch, inject, patch, or otherwise modify the game process.
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "wowmod/json.hpp"
#include "wowmod/mapping.hpp"
#include "wowmod/util.hpp"

namespace wowmod {

struct ArctiumMappedFile {
  uint32_t file_id = 0;
  std::string game_path;   // Path in the mapping/listfile, normalized with '/'.
  std::string local_path;  // Absolute path to the replacement file on disk.
  uint64_t size = 0;
};

struct ArctiumFilePlan {
  std::string files_root;
  std::vector<ArctiumMappedFile> files;  // Sorted by FileDataID, one row per ID.
  size_t scanned_files = 0;
  size_t unmapped_files = 0;
  size_t duplicate_ids = 0;
  size_t invalid_ids = 0;
  std::string error;

  Json to_json() const;
};

// Mirrors Arctium's mapping behavior: enumerate a configurable files root, keep only local files
// whose relative path exists in a FileDataID mapping, and produce a unique ID -> full local path
// table. Unrelated files in the root are ignored. Duplicate IDs are resolved deterministically by
// retaining the first path in sorted enumeration order (rather than filesystem-dependent order).
ArctiumFilePlan plan_arctium_files(const std::string& files_root,
                                   const MappingTable& mappings,
                                   Diagnostics* diag = nullptr);

}  // namespace wowmod
