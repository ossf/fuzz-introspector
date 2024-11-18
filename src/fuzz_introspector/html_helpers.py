# Copyright 2022 Fuzz Introspector Authors
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
"""Module for creating HTML reports"""

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
)

import os
import bs4
import logging
from datetime import datetime
from enum import Enum

from fuzz_introspector import utils, constants
from fuzz_introspector.datatypes import fuzzer_profile, project_profile

logger = logging.getLogger(name=__name__)


class HTML_HEADING(Enum):
    H1 = 1
    H2 = 2
    H3 = 3
    H4 = 4
    H5 = 5
    H6 = 6


class HTML_TOC_ENTRY:
    """Entry in the table of contents"""

    def __init__(self, entry_title: str, href_link: str,
                 heading_type: HTML_HEADING):
        self.entry_title = entry_title
        self.href_link = href_link
        self.heading_type = heading_type


class HtmlTableOfContents:
    """Helper class for representing a table of content"""

    def __init__(self):
        self.entries: List[HTML_TOC_ENTRY] = []

    def add_entry(self, entry_title, href_link, heading_type):
        toc_entry = HTML_TOC_ENTRY(entry_title, href_link, heading_type)
        self.entries.append(toc_entry)


class HTMLConclusion:
    """Represents high-level conclusions in HTML report

    :ivar int severity: Importance of conclusion. 100 max, 0 lowest.
    :ivar str title: One line description of conclusion.
    :ivar str description: Extended description.
    """

    def __init__(self, severity, title, description):
        self.title = title
        self.severity = severity
        self.description = description

    def __lt__(self, other):
        """Implemented for sorting list of conclusions"""
        return self.severity < other.severity


def html_table_add_row(elems: List[Any]) -> str:
    html_str = "<tr>\n"
    for elem in elems:
        html_str += f"<td>{elem}</td>\n"
    html_str += "</tr>\n"
    return html_str


def html_get_header(title: str = "Fuzz introspector") -> str:
    gtag_tracking = ""
    try:
        gtag = os.environ['G_ANALYTICS_TAG']
        gtag_tracking += f"""<!-- Google tag (gtag.js) -->
                <script async src="https://www.googletagmanager.com/gtag/js?id={gtag}"></script>
                <script>
                  window.dataLayer = window.dataLayer || [];
                  function gtag(){{dataLayer.push(arguments);}}
                  gtag('js', new Date());

                  gtag('config', '{gtag}');
                </script>\n"""
    except KeyError:
        gtag_tracking = ""

    header = f"""<html>
    <head>
        {gtag_tracking}
        <link
            rel='stylesheet'
            href='prism.css'>
        <link
            rel="stylesheet"
            href="https://unpkg.com/dracula-prism/dist/css/dracula-prism.css">
    </head>
        <body>
            <script
                src="https://code.jquery.com/jquery-3.6.0.min.js"
                integrity="sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4="
                crossorigin="anonymous">
            </script>
            <script
                src='https://cdn.datatables.net/1.10.25/js/jquery.dataTables.min.js'>
            </script>
            <link
                rel='stylesheet'
                href='https://cdn.datatables.net/1.10.25/css/jquery.dataTables.min.css'>
            <link
                rel='stylesheet'
                href='styles.css'>
            <link
                rel='stylesheet'
                href='https://cdn.datatables.net/buttons/2.2.2/css/buttons.dataTables.min.css'>"""
    # Add navbar to header
    header = header + html_get_navbar(title)
    return header


def html_get_navbar(title: str) -> str:
    navbar = f"""
    <div class="top-navbar">
        <div class="top-navbar-title-wrapper">
            <div class="top-navbar-title" style="margin-bottom: 10px; font-size:25px">
                { title }
            </div>
            <div style="margin:0; font-size: 10px">
              For issues and ideas:
              <a href="https://github.com/ossf/fuzz-introspector/issues"
                 style="color:#FFFFFF;">
                https://github.com/ossf/fuzz-introspector/issues
              </a>
            </div>
        </div>
    </div>"""
    return navbar


def create_pfc_button(profiles: List[fuzzer_profile.FuzzerProfile],
                      coverage_url: str) -> str:
    html_string = ""
    html_string += """
                    <div class="yellow-button-wrapper"
                        style="position: relative; margin: 5px 0 30px 0">
                        <div class="yellow-button"
                        onclick="displayCollapseByName()" id="per-fuzzer-coverage-button">
                            Per-fuzzer coverage
                        </div>
                    <div class="per-fuzzer-coverage-dropdown" id="per-fuzzer-coverage-dropdown">"""
    for profile in profiles:
        target_name = profile.identifier
        target_coverage_url = utils.get_target_coverage_url(
            coverage_url, target_name, profile.target_lang)
        # get_target_coverage_url gives base folder. We must specify
        # HTML file for it to work on gcloud as there is no automatic
        # redirection.
        if profile.target_lang == "c-cpp":
            target_coverage_url += "/report.html"
        elif profile.target_lang == "python":
            target_coverage_url += "/index.html"
        elif profile.target_lang == "jvm":
            target_coverage_url += "/index.html"
        elif profile.target_lang == "rust":
            target_coverage_url += "/report.html"

        html_string += f"""
            <a href="{target_coverage_url}">
                <div class="pfc-list-item">
                    {target_name}
                </div>
            </a>"""
    html_string += "</div></div>"
    return html_string


def html_get_table_of_contents(
        table_of_contents: HtmlTableOfContents, coverage_url: str,
        profiles: List[fuzzer_profile.FuzzerProfile],
        proj_profile: project_profile.MergedProjectProfile) -> str:
    per_fuzzer_coverage_button = create_pfc_button(profiles, coverage_url)

    if proj_profile.target_lang == "c-cpp":
        cov_index = "report.html"
    elif proj_profile.target_lang == "python":
        cov_index = "index.html"
    elif proj_profile.target_lang == "jvm":
        cov_index = "index.html"
    elif proj_profile.target_lang == "rust":
        cov_index = "report.html"

    html_toc_string = ""
    html_toc_string += f"""<div class="left-sidebar">\
                            <div class="left-sidebar-content-box"
                                style="display:flex;flex-direction:column;
                                 padding: 0 20px; margin-top: 30px">
                                <div class="yellow-button-wrapper"
                                    style="position: relative; margin: 30px 0 5px 0">
                                    <a href="{coverage_url}/{cov_index}">
                                        <div class="yellow-button">
                                            Project coverage
                                        </div>
                                    </a>
                                </div>
                        """
    if proj_profile.target_lang != "python":
        html_toc_string += f"{per_fuzzer_coverage_button}"

    html_toc_string += """</div>
                            <div class="left-sidebar-content-box">\
                                <h2 style="margin-top:0px">Table of contents</h2>"""

    for toc_entry in table_of_contents.entries:
        indentation = (toc_entry.heading_type.value - 1) * 16
        html_toc_string += "<div style='margin-left: %spx'>" % indentation
        html_toc_string += "    <a href=\"#%s\">%s</a>\n" % (
            toc_entry.href_link, toc_entry.entry_title)
        html_toc_string += "</div>\n"
    html_toc_string += '    </div>\
                        </div>'

    return html_toc_string


def html_add_header_with_link(header_title: str,
                              title_type: HTML_HEADING,
                              table_of_contents: HtmlTableOfContents,
                              link: Optional[str] = None,
                              experimental: Optional[bool] = False) -> str:
    if link is None:
        link = header_title.replace(" ", "-")

    if not experimental:
        table_of_contents.add_entry(header_title, link, title_type)

    html_attributes = ""
    if title_type == HTML_HEADING.H1 or experimental:
        html_attributes += " class=\"report-title\""

    html_string = f"<a id=\"{link}\">"
    html_string += (
        f"<h{title_type.value} {html_attributes}>{header_title}</h{title_type.value}>\n"
    )
    return html_string


def html_create_table_head(table_head: str,
                           items: List[Tuple[str, str]],
                           sort_by_column: int = 0,
                           sort_order: str = "asc") -> str:
    html_str = (
        f"<table id='{table_head}' class='cell-border compact stripe' "
        f"data-sort-by-column='{sort_by_column}' data-sort-order='{sort_order}'>"
    )
    html_str += "<thead><tr>\n"
    for column_title, column_description in items:
        if column_description == "":
            html_str += f"<th>{column_title}</th>\n"
        else:
            html_str += f"<th title='{column_description}'>{column_title}</th>\n"
    html_str += "</tr></thead><tbody>"
    return html_str


def get_simple_box(title: str, value: str) -> str:
    """Wraps a title and value in a simle HTML div box, where the box has some
    simple borders.
    """

    return f"""<div class="report-box"
                    style="flex: 1; display: flex; flex-direction: column;">
        <div style="font-size: 0.9rem;">
          {title}
        </div>
        <div style="font-size: 1.2rem; font-weight: 550;">
          {value}
        </div>
      </div>"""


def create_collapsible_element(non_collapsed: str, collapsed: str,
                               collapsible_id: str) -> str:
    """Creates a string followed by a <div> that is collapsible. We use this
    for displaying items in tables where the full substance of the item is
    too large to display by default for all items, but we still want the user
    to be able to see the full substance of the item on demand.
    """
    return f"""{ non_collapsed } : <div
    class='wrap-collabsible'>
        <input id='{collapsible_id}'
               class='toggle'
               type='checkbox'>
            <label for='{collapsible_id}'
                   class='lbl-toggle'>
                View List
            </label>
        <div class='collapsible-content'>
            <div class='content-inner'>
                <p>
                    {collapsed}
                </p>
            </div>
        </div>
    </div>"""


def create_percentage_graph(title: str, numerator: int,
                            denominator: int) -> str:
    """Creates a percentage tag within a <div> tag. This is used to show
    "how much X is of Y" for a {numerator, denominator} pair.
    """
    try:
        percentage = round(float(numerator) / float(denominator), 2) * 100.0
    except ZeroDivisionError:
        percentage = 0.0

    subtitle = f"{numerator} / {denominator}"
    return f"""<div style="flex:1; margin-right: 20px"class="report-box mt-0">
            <div style="font-weight: 600; text-align: center;">
                {title}
            </div>
            <div class="flex-wrapper">
              <div class="single-chart">
                <svg viewBox="0 0 36 36" class="circular-chart green">
                  <path class="circle-bg"
                    d="M18 2.0845
                      a 15.9155 15.9155 0 0 1 0 31.831
                      a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  <path class="circle"
                    stroke-dasharray="{percentage}, 100"
                    d="M18 2.0845
                      a 15.9155 15.9155 0 0 1 0 31.831
                      a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  <text x="18" y="20.35" class="percentage">{str(percentage)[:4]}%</text>
                </svg>
              </div>
            </div>
            <div style="font-size: .9rem; color: #b5b5b5; text-align: center">
              {subtitle}
            </div>
        </div>"""


def create_conclusions_box(conclusions: List[HTMLConclusion]) -> str:
    """Creates a <div> with all conclusions displayed. Conclusions of highest
    severity are placed lowest (positive conclusiosn at top, negative at
    bottom).
    """
    html_string = ""
    html_string += "<div class=\"high-level-conclusions-wrapper\">"

    # Sort conclusions to show highest level (positive conclusion) first
    conclusions = list(reversed(sorted(conclusions)))
    for conclusion in conclusions:
        if conclusion.severity < 5:
            conclusion_color = "red"
        elif conclusion.severity < 8:
            conclusion_color = "yellow"
        else:
            conclusion_color = "green"
        html_string += f"""<div class="line-wrapper">
    <div class="high-level-conclusion { conclusion_color }-conclusion collapsed">
    { conclusion.title }
        <div class="high-level-extended" style="background:transparent; overflow:hidden">
            { conclusion.description }
        </div>
    </div>
</div>"""
    # TODO(david)
    # The below </div> was there when refactoring, but it does not look like
    # it shuold be there. Verify.
    html_string += "</div>"
    return html_string


def create_calltree_color_distribution_table(color_list: List[str]) -> str:
    html_string = ""
    color_dictionary: Dict[str, int] = {}
    for color in color_list:
        color_dictionary[color] = color_dictionary.get(color, 0) + 1

    html_string += ("<p>The distribution of callsites in terms of coloring is")
    html_string += ("<table><tr>"
                    "<th style=\"text-align: left;\">Color</th>"
                    "<th style=\"text-align: left;\">Runtime hitcount</th>"
                    "<th style=\"text-align: left;\">Callsite count</th>"
                    "<th style=\"text-align: left;\">Percentage</th>"
                    "</tr>")
    for _min, _max, color, rgb_code in constants.COLOR_CONSTANTS:
        html_string += (f"<tr><td style=\"color:{color}; "
                        f"text-shadow: -1px 0 black, 0 1px black, "
                        f"1px 0 black, 0 -1px black;\"><b>{color}</b></td>")
        if _max == 1:
            interval = "0"
        elif _max > 1000:
            interval = f"{_min}+"
        else:
            interval = f"[{_min}:{_max-1}]"
        html_string += f"<td>{interval}</td>"
        cover_count = color_dictionary.get(color, 0)
        html_string += f"<td>{cover_count}</td>"
        if len(color_list) > 0:
            f1 = float(cover_count)
            f2 = float(len(color_list))
            percentage_c = (f1 / f2) * 100.0
        else:
            percentage_c = 0.0
        percentage_s = str(percentage_c)[0:4]
        html_string += f"<td>{percentage_s}%</td>"
        html_string += "</tr>"

    # Add a row with total amount of callsites
    html_string += f"<tr><td>All colors</td><td>{len(color_list)}</td><td>100</td></tr>"
    html_string += "</table>"
    html_string += "</p>"
    return html_string


def create_horisontal_calltree_image(image_name: str,
                                     profile: fuzzer_profile.FuzzerProfile,
                                     dump_files: bool) -> List[str]:
    """
    Creates a horisontal image of the calltree. The height is fixed and
    each element on the x-axis shows a node in the calltree in the form
    of a rectangle. The rectangle is red if not visited and green if visited.
    """
    try:
        import matplotlib.pyplot as plt
        from matplotlib.patches import Rectangle
    except ModuleNotFoundError:
        # It's useful to avoid this in CIFuzz because building the fuzzers with
        # matplotlib costs a lot of time (10 minutes) in the CI, which we prefer
        # to avoid.
        logger.info("Could not import matplotlib. No bitmaps are created")
        return []

    logger.info(f"Creating image {image_name}")

    # Get the callsites of the profile as a list of colors.
    color_list: List[str] = [cs.cov_color for cs in profile.get_callsites()]
    logger.info(f"- extracted the callsites ({len(color_list)} nodes)")

    # Show one read rectangle if the list is empty. An alternative is
    # to not include the image at all.
    if len(color_list) == 0:
        color_list = ['red']

    # Create a plot
    fig, ax = plt.subplots()
    ax.clear()
    fig.set_size_inches(15, 2.5)
    ax.plot()

    # Create our rectangles
    curr_x = 0.0
    curr_size = 1.0
    curr_color = color_list[0]
    for i in range(1, len(color_list)):
        if curr_color == color_list[i]:
            curr_size += 1.0
        else:
            ax.add_patch(
                Rectangle((curr_x, 0.0), curr_size, 1.0, color=curr_color))

            # Start next color area
            curr_x += curr_size
            curr_color = color_list[i]
            curr_size = 1.0
    # Plot the last case
    ax.add_patch(Rectangle((curr_x, 0.0), curr_size, 1.0, color=curr_color))
    logger.info("- iterated over color list")

    # Save the image
    if dump_files:
        logger.info("- saving image")
        ax.set_yticklabels([])
        ax.set_yticks([])
        xlabel = ax.set_xlabel("Callsite index")

        plt.title(image_name.replace(".png", "").replace("_colormap", ""))
        fig.tight_layout()
        fig.savefig(image_name, bbox_extra_artists=[xlabel])
        logger.info("- image saved")
    return color_list


def html_get_report_creation_tag() -> str:
    html_overview = "<b>Report generation date:</b>"
    html_overview += datetime.today().strftime('%Y-%m-%d')
    html_overview += "<br>"
    return html_overview


def prettify_html(html_doc: str) -> str:
    """Prettify a HTML document."""
    soup = bs4.BeautifulSoup(html_doc, "html.parser")
    try:
        pretty_html = soup.prettify()
    except RecursionError:
        pretty_html = html_doc
    return pretty_html


def wrap_link(url, text):
    return f"<a href='{url}'>{text}</a>"


def create_coded_text(text):
    return f"<code class='language-clike'>\n{text}\n</code>"
