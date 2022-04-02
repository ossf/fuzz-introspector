$( document ).ready(function() {
    createTables();

    // Scroll effect for showing in the menu where you are on the page
    $(".content-section").on('scroll', e => {
      $('.report-title').each(function() {
        if($(this).offset().top - 200 < $(window).scrollTop()) {
          var elemId;
          elemId = $(this).closest("a").attr('id');
          $(".left-sidebar-content-box > div > a").each(function( index ) {
            //console.log("link: ", $(this).attr("href").replace("#", ""));
            if($(this).attr("href").replace("#", "")===elemId) {
              if(!$(this).hasClass("activeMenuText")) {
                $(this).addClass("activeMenuText");
              }
            } else {
              if($(this).hasClass("activeMenuText")) {
                $(this).removeClass("activeMenuText");
              }
            }
          })
        };
      });
    });
});

// createTables instantiates the datatables.
// During this process the number of rows is 
// checked, and some elements are left out of
// the datatables. Currently, these decisions
// are implemented:
// 1: Only show pagination, length change
//    dropdown when there are more than 10 rows.
// 2: Only show search field when there are more
//    than 4 rows. (This could potentially be change
//    to specific tables instead where fuzzer names
//    vary)
function createTables() {
  $.each(tableIds, function(index, value) {
    createTable(value);
  });




}

function createTable(value) {
  // Get number of rows in this table
  var rowCount = $('#'+value+' tr').length;
  var sortByColumn = $('#'+value).data('sort-by-column');
  var sortOrder = $('#'+value).data('sort-order');
  

  var bPaginate;
  var bLengthChange;
  var bInfo;
  var bFilter;

  /*if(rowCount<6) {
    bFilter = false;
  } else {
    bFilter = true;
  }*/
    bFilter = true;

  if(rowCount<12) {
    bPaginate = false;
    bLengthChange = false;
    bInfo = false;
  } else {      
    bPaginate = true;
    bLengthChange = true;
    bInfo = true;
  }      
    bPaginate = true;
    bLengthChange = true;
    bInfo = true;

  var tableConfig = {'bPaginate': bPaginate,
                          'bLengthChange': bLengthChange,
                          'bInfo': bInfo,
                          'bFilter': bFilter,
                          'pageLength': 10}
  var language = {"lengthMenu": "_MENU_ per page",
                  "searchPlaceholder": "Search table",
                  "search": "_INPUT_"}
  tableConfig.language = language;

  
  tableConfig.order = [[sortByColumn, sortOrder]]

  if(value==="fuzzers_overview_table" || value==="all_functions_overview_table") {
    tableConfig.columns = [
      {data: "Func name"},
      {data: "Functions filename"},
      {data: "Args"},
      {data: "Function call depth"},
      {data: "Reached by Fuzzers"},
      {data: "Fuzzers runtime hit"},
      {data: "Func lines hit %"},
      {data: "I Count"},
      {data: "BB Count"},
      {data: "Cyclomatic complexity"},
      {data: "Functions reached"},
      {data: "Reached by functions"},
      {data: "Accumulated cyclomatic complexity"},
      {data: "Undiscovered complexity"}]
  }
  
  // Create the table:
  var table = $('#'+value).DataTable(tableConfig);

  if(value==="fuzzers_overview_table" || value==="all_functions_overview_table") {

    var dataSet;

    if(value==="fuzzers_overview_table") {
      dataSet = all_functions_table_data;
    }else if(value==="all_functions_overview_table") {
      dataSet = analysis_1_data;
    }

    for(var i=0;i<dataSet.length;i++) {
      var rowData = dataSet[i]

      var styledFuncName = styleFuncName(rowData["func_name"], true, "#")

      table.rows.add([{
        "Func name": styledFuncName,
        "Functions filename": rowData["function_source_file"],
        "Args": rowData["args"],
        "Function call depth": rowData["function_depth"],
        "Reached by Fuzzers": rowData["reached_by_fuzzers"],
        "Fuzzers runtime hit": rowData["func_hit_at_runtime_row"],
        "Func lines hit %": rowData["hit_percentage"],
        "I Count": rowData["i_count"],
        "BB Count": rowData["bb_count"],
        "Cyclomatic complexity": rowData["cyclomatic_complexity"],
        "Functions reached": rowData["functions_reached"],
        "Reached by functions": rowData["incoming_references"],
        "Accumulated cyclomatic complexity": rowData["total_cyclomatic_complexity"],
        "Undiscovered complexity": rowData["new_unreached_complexity"]
      }]);
    }
    table.draw();
  }



}

function styleFuncName(funcName, withLink=false, url=null) {
  if(withLink===true) {
    return `
      <a href='${url}'><code class='language-clike'>
        ${funcName}
      </code></a>
      `;
  }else{
    return `
      <code class='language-clike'>
        ${funcName}
      </code>
      `;
  }
}