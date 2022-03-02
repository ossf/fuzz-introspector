$( document ).ready(function() {
    createTables();
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
    createTable(value, false);
  });

  // Tables with the "source code lines column" are
  // sorted by that column:
  recreateSCLTables();
}

function createTable(value, sortByCustomHeader, columnIndex=0) {
  // Get number of rows in this table
    var rowCount = $('#'+value+' tr').length;
    

    var bPaginate;
    var bLengthChange;
    var bInfo;
    var bFilter;

    if(rowCount<6) {
      bFilter = false;
    } else {
      bFilter = true;
    }

    if(rowCount<12) {
      bPaginate = false;
      bLengthChange = false;
      bInfo = false;
    } else {      
      bPaginate = true;
      bLengthChange = true;
      bInfo = true;
    }

    var tableConfig = {'bPaginate': bPaginate,
                            'bLengthChange': bLengthChange,
                            'bInfo': bInfo,
                            'bFilter': bFilter}

    if(sortByCustomHeader) {
      tableConfig.order = [[columnIndex, "desc"]]
    }
    
    // Create the table:
    $('#'+value).DataTable(tableConfig);

}

function recreateSCLTables() {
  var tables = document.getElementsByTagName("table");

  for (var i = 0; i < tables.length; i++) {
    var table = tables[i];
    var tableId = table.id;
    var ths = table.getElementsByTagName("th");

    for (var j = 0; j < ths.length; j++) {
      var text = ths[j].innerText;
      if(text==="source code lines") {
        $('#'+tableId).DataTable().destroy();
        createTable(tableId, true, j);
      }
    }
  }

}