// Arctium-compatible file table preparation.
// SPDX-License-Identifier: MIT
#include "wowmod/arctium.hpp"

#include <map>
#include <string>
#include <utility>

#include "wowmod/json.hpp"

namespace wowmod {

Json ArctiumFilePlan::to_json() const {
  Json out = Json::make_object();
  out.set("backend", Json::make_string("arctium-style-fileid-map"));
  out.set("status", Json::make_string("preflight-only"));
  out.set("clientModified", Json::make_bool(false));
  out.set("hookInstalled", Json::make_bool(false));
  out.set("filesRoot", Json::make_string(files_root));
  out.set("mappedFiles", Json::make_number(static_cast<double>(files.size())));
  out.set("scannedFiles", Json::make_number(static_cast<double>(scanned_files)));
  out.set("unmappedFiles", Json::make_number(static_cast<double>(unmapped_files)));
  out.set("duplicateIds", Json::make_number(static_cast<double>(duplicate_ids)));
  out.set("invalidIds", Json::make_number(static_cast<double>(invalid_ids)));
  if (!error.empty()) out.set("error", Json::make_string(error));
  Json rows = Json::make_array();
  for (const auto& f : files) {
    Json row = Json::make_object();
    row.set("fileId", Json::make_number(f.file_id));
    row.set("gamePath", Json::make_string(f.game_path));
    row.set("localPath", Json::make_string(f.local_path));
    row.set("size", Json::make_number(static_cast<double>(f.size)));
    rows.push(row);
  }
  out.set("files", rows);
  return out;
}

ArctiumFilePlan plan_arctium_files(const std::string& files_root,
                                   const MappingTable& mappings,
                                   Diagnostics* diag) {
  ArctiumFilePlan plan;
  plan.files_root = absolute_path(files_root);
  if (!dir_exists(files_root)) {
    plan.error = "Arctium filesDir is not a directory: " + files_root;
    if (diag) diag->error("arctium.filesDir", plan.error);
    return plan;
  }

  std::string list_error;
  const auto local_files = list_files_recursive(files_root, &list_error);
  if (!list_error.empty()) {
    plan.error = list_error;
    if (diag) diag->error("arctium.filesDir", list_error);
    return plan;
  }

  std::map<uint32_t, ArctiumMappedFile> by_id;
  plan.scanned_files = local_files.size();
  for (const auto& relative : local_files) {
    const auto id = mappings.id_for_path(relative);
    if (!id) {
      ++plan.unmapped_files;
      continue;
    }
    if (*id == 0 || *id > UINT32_MAX) {
      ++plan.invalid_ids;
      if (diag) diag->warn("arctium.mapping", "FileDataID 超出 32 位范围，忽略: " +
                                                    std::to_string(*id) + ";" + relative);
      continue;
    }

    ArctiumMappedFile candidate;
    candidate.file_id = static_cast<uint32_t>(*id);
    candidate.game_path = normalize_path(relative);
    candidate.local_path = to_native_path(absolute_path(join_path(files_root, relative)));
    candidate.size = file_size(candidate.local_path);

    const auto it = by_id.find(candidate.file_id);
    if (it != by_id.end()) {
      ++plan.duplicate_ids;
      if (diag) diag->warn("arctium.mapping", "FileDataID 重复，保留排序靠前的本地文件: #" +
                                                    std::to_string(candidate.file_id) + " (" +
                                                    it->second.game_path + " ; " + candidate.game_path + ")");
      continue;
    }
    by_id.emplace(candidate.file_id, std::move(candidate));
  }

  plan.files.reserve(by_id.size());
  for (auto& pair : by_id) plan.files.push_back(std::move(pair.second));
  if (diag) {
    diag->info("arctium", "映射表准备完成: " + std::to_string(plan.files.size()) +
                              " 个 ID -> 松散文件，扫描 " + std::to_string(plan.scanned_files) + " 个文件");
  }
  return plan;
}

}  // namespace wowmod
