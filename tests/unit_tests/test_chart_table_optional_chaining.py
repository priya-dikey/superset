# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Regression test for GitHub issue #5.

Ensures that `otherTabData` uses optional chaining (`?.`) in ChartTable.tsx
so that the component does not throw a TypeError when `otherTabData` is
undefined.
"""

from pathlib import Path


def test_chart_table_uses_optional_chaining_on_other_tab_data() -> None:
    """Verify otherTabData.filter uses optional chaining to avoid TypeError."""
    chart_table_path = (
        Path(__file__).resolve().parents[2]
        / "superset-frontend"
        / "src"
        / "features"
        / "home"
        / "ChartTable.tsx"
    )
    source = chart_table_path.read_text()
    assert "otherTabData?.filter(" in source, (
        "otherTabData must use optional chaining (?.) before .filter() "
        "to avoid TypeError when the prop is undefined (see issue #5)"
    )
    assert "otherTabData.filter(" not in source.replace(
        "otherTabData?.filter(", ""
    ), (
        "Found a bare otherTabData.filter() call without optional chaining"
    )
