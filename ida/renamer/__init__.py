# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
capa auto-renamer: rename IDA functions from capa rule matches.

layout:
  - naming.py:      rule name -> valid identifier (pure Python, no IDA dependency)
  - proposals.py:   capa result document -> one rename proposal per function (pure Python)
  - ida_backend.py: fetch/compute capa results, apply and undo renames in the IDB
  - plugin.py:      IDA plugin, chooser and actions
"""
