$( document ).ready(function() {
    createTables();

    // Scroll effect for showing in the menu where you are on the page
    $(".content-section").on('scroll', e => {
      $('.report-title').each(function() {
        if($(this).offset().top - 200 < $(window).scrollTop()) {
          var elemId;
          elemId = $(this).closest("a").attr('id');
          $(".left-sidebar-content-box > div > a").each(function( index ) {
              console.log("link: ", $(this).attr("href").replace("#", ""));
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
  var language = {"lengthMenu": "_MENU_ per page",
                  "searchPlaceholder": "Search table",
                  "search": "_INPUT_"}
  tableConfig.language = language;

  
  tableConfig.order = [[sortByColumn, sortOrder]]
  
  // Create the table:
  $('#'+value).DataTable(tableConfig);
}