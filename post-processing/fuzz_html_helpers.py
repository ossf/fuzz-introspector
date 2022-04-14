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
    List,
    Tuple,
)


def html_table_add_row(elems: List[Any]) -> str:
    html_str = "<tr>\n"
    for elem in elems:
        html_str += f"<td>{elem}</td>\n"
    html_str += "</tr>\n"
    return html_str


def html_get_header(calltree: bool = False,
                    title: str = "Fuzz introspector") -> str:
    header = """<html>
    <head>
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
                href='styles.css'>"""
    # Add navbar to header
    header = header + html_get_navbar(title)
    if calltree:
        header = header + "<div class='content-wrapper calltree-page'>"
    else:
        header = header + "<div class='content-wrapper report-page'>"
    return header


def html_get_navbar(title: str) -> str:
    navbar = f"""<div class="top-navbar">
    <div class="top-navbar-accordion">
        <svg
            viewBox="0 0 24 24"
            preserveAspectRatio="xMidYMid meet"
            focusable="false"
            style="pointer-events: none; display: block; width: 100%; height: 100%;">
            <g>
                <path d="M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z">
                </path>
            </g>
        </svg>
    </div>
    <div class="top-navbar-title">
        { title }
    </div>
</div>"""
    return navbar


def html_get_table_of_contents(toc_list: List[Tuple[str, str, int]]) -> str:
    html_toc_string = ""
    html_toc_string += '<div class="left-sidebar">\
                            <div class="left-sidebar-content-box">\
                                <h2>Table of contents</h2>'
    for k, v, d in toc_list:
        indentation = d * 16
        html_toc_string += "<div style='margin-left: %spx'>" % indentation
        html_toc_string += "    <a href=\"#%s\">%s</a>\n" % (v, k)
        html_toc_string += "</div>\n"
    html_toc_string += '    </div>\
                        </div>'
    return html_toc_string


def html_add_header_with_link(header_title: str,
                              title_type: int,
                              toc_list: List[Tuple[str, str, int]],
                              link: str = None) -> str:
    if link is None:
        link = header_title.replace(" ", "-")
    toc_list.append((header_title, link, title_type - 1))
    html_string = f"<a id=\"{link}\">"
    html_string += f"<h{title_type} class=\"report-title\">{header_title}</h{title_type}>\n"
    return html_string


def html_create_table_head(
        table_head: str,
        items: List[Tuple[str, str]],
        sort_by_column: int = 0,
        sort_order: str = "asc") -> str:
    html_str = (f"<table id='{table_head}' class='cell-border compact stripe' "
                f"data-sort-by-column='{sort_by_column}' data-sort-order='{sort_order}'>")
    html_str += "<thead><tr>\n"
    for column_title, column_description in items:
        if column_description == "":
            html_str += f"<th>{column_title}</th>\n"
        else:
            html_str += f"<th title='{column_description}'>{column_title}</th>\n"
    html_str += "</tr></thead><tbody>"
    return html_str
