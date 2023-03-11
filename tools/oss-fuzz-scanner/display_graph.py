# Copyright 2023 Fuzz Introspector Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from datetime import datetime
from matplotlib import pyplot as plt, dates as mdates

import scanner


def get_complexities(project_name):
    """Get the complexities of a project over time."""

    # Get reports across 4 days with a 10 day interval between the reports.
    report_generator = scanner.get_all_reports([project_name], 5, 10)

    complexities = []
    for project, date_as_str, introspector_project in report_generator:
        complexities.append(
            (project, introspector_project.proj_profile.reached_complexity,
             len(introspector_project.proj_profile.
                 get_all_runtime_covered_functions()), date_as_str))
    return complexities


complexities = get_complexities('htslib')

# Convert the complexities into x,y coordinates we can plot.
x_axis = []
y_axis = []
for proj_name, reachable_funs, covered_funcs, date in complexities:
    y_axis.append(covered_funcs)

    # Convert e.g. 20221001 to 2022-10-0
    x_axis.append(date[:4] + "-" + date[4:6] + "-" + date[6:])

print("Dumping data")
print("coverage, date")
for idx in range(len(x_axis)):
    print(str(x_axis[idx]) + ", " + str(y_axis[idx]))

print("Showing graph")

plt.rcParams["figure.figsize"] = [7.50, 3.50]
plt.rcParams["figure.autolayout"] = True

x = [datetime.strptime(d, "%Y-%m-%d").date() for d in x_axis]
ax = plt.gca()
ax.plot(x_axis, y_axis)

# Show the figure.
plt.show()
