$( document ).ready(function() {
    $('.coverage-line-inner').click(function(){
      var wrapper = $(this).closest(".calltree-line-wrapper");
      var wrapperClasses = $(wrapper).attr("class").split(/\s+/);
      var level;
      for(i=0;i<wrapperClasses.length;i++) {
        if(wrapperClasses[i].includes("level-")) {
          level = parseInt(wrapperClasses[i].split("-")[1]);
        }
      }
      var nextLevel = "level-"+(level+1);
      var childLineWrapper = $(this).closest(".coverage-line").find(".calltree-line-wrapper."+nextLevel);
      if($(childLineWrapper).hasClass("open")) {
        $(childLineWrapper).height($(childLineWrapper).get(0).scrollHeight).height("0px").toggleClass("open");
      } else {
        $(childLineWrapper).height($(childLineWrapper).get(0).scrollHeight).toggleClass("open");
        // If we don't use a timeout here, then the height is changed before the csss transition
        // is executed, and the css transition will not be used. We have to set auto height here,
        // because we nested collapsibles.
        setTimeout(function() {
          $(childLineWrapper).height("auto");
        }, 200);
      }
      if($(this).hasClass("expand-symbol")) {
        $(this).removeClass("expand-symbol");
        $(this).addClass("collapse-symbol");
      }else if($(this).hasClass("collapse-symbol")) {
        $(this).removeClass("collapse-symbol");
        $(this).addClass("expand-symbol");
      }
  });

  // Create nav bar
  createNavBar();

  // Add blocker lines to the calltree
  addFuzzBlockerLines();

  // Add the expand symbols to all nodes that are expandable
  addExpandSymbols();


  addNavbarClickEffects();
  addCollapsibleFunctionsToDropdown();

  document.addEventListener('click', function(e) {
    e = e || window.event;
    var target = e.target;
    var menuElement = document.getElementById("myDropdown");
    if(isDescendant(menuElement, target)) {
       e.stopPropagation();
    }
  }, false);



  var innerNodes = document.getElementsByClassName("collapse-function-with-name");

  for (var i = 0; i < innerNodes.length; i++) {
    innerNodes[i].addEventListener('click', function(e) {
      e = e || window.event;
      var target = e.target;
      var funcName = target.innerText;

      // Close all nodes with this funcName:
      var elems = document.getElementsByClassName("coverage-line-inner collapse-symbol");
      for(var i=0;i<elems.length;i++) {
        if(elems[i].querySelector(".language-clike").innerText.trim()===funcName) {
          elems[i].click()
        }
      }
    }, false);
  }


  const checkbox = document.getElementById('free-chckbox');
  checkbox.addEventListener('change', (event) => {
    hideNodesWithText("free")
  })

  const checkbox2 = document.getElementById("abort-chckbox");
  checkbox2.addEventListener('change', (event) => {
    hideNodesWithText("abort")
  })

  const checkbox3 = document.getElementById("malloc-chckbox");
  checkbox3.addEventListener('change', (event) => {
    hideNodesWithText("malloc")
  })

  const checkbox4 = document.getElementById("calloc-chckbox");
  checkbox4.addEventListener('change', (event) => {
    hideNodesWithText("calloc")
  })

  const checkbox5 = document.getElementById("exit-chckbox");
  checkbox5.addEventListener('change', (event) => {
    hideNodesWithText("exit")
  })

  const checkbox6 = document.getElementById("memcmp-chckbox");
  checkbox6.addEventListener('change', (event) => {
    hideNodesWithText("memcmp")
  })

  const checkbox7 = document.getElementById("strlen-chckbox");
  checkbox7.addEventListener('change', (event) => {
    hideNodesWithText("strlen")
  })

  scrollOnLoad();
});

// Scrolls to a node if the "scrollToNode" parameters is given
function scrollOnLoad() {
  const queryString = window.location.search;
  const urlParams = new URLSearchParams(queryString);
  const scrollToNode = urlParams.get('scrollToNode')
  if(scrollToNode!==null) {
    var dataValue = "[data-calltree-idx='"+scrollToNode+"']";
    var elementToScrollTo = document.querySelector(dataValue);
    if(elementToScrollTo===null) {
      return
    }
    elementToScrollTo.style.background = "#ffe08c";
    document.querySelector(".calltree-content-section").scrollTop = elementToScrollTo.offsetTop-500;
  }
}

// Checks whether child is a descendant of parent.
function isDescendant(parent, child) {
  var node = child.parentNode;
  while (node != null) {
    if (node == parent) {
      return true;
    }
    node = node.parentNode;
  }
  return false;
}

// Adds the fuzz blocker lines to the nodes in the calltree
function addFuzzBlockerLines() {
  var coverageLines;
  coverageLines = document.getElementsByClassName("coverage-line-inner");
  for(var j=0;j<coverageLines.length;j++) {
    var thisDataIdx = coverageLines[j].getAttribute("data-calltree-idx");
    if(thisDataIdx!==null && fuzz_blocker_idxs.includes(thisDataIdx)) {
      coverageLines[j].classList.add("with-fuzz-blocker-line");
      let infoBtn = document.createElement("div");
      infoBtn.classList.add("fuzz-blocker-info-btn");
      infoBtn.innerText = "FUZZ BLOCKER";
      coverageLines[j].append(infoBtn);
    }
  }
}

/* When the user clicks on the button,
toggle between hiding and showing the dropdown content */
function displayNavBar() {
  document.getElementById("myDropdown").classList.toggle("show");
}
function displayFontSizeDropdown() {
  document.getElementById("fontSizeDropdown").classList.toggle("show");
}
function displayCollapseByName() {
  document.getElementById("collapseByNameDropdown").classList.toggle("show");
}

function createNavBar() {
  // Create the navbar wrapper element
  let e = document.createElement("div");
  e.classList.add("calltree-navbar");

  // Add buttons to the navbar
  addBackButton(e)
  addShowIdxButton(e);
  addExpandAllBtn(e);
  addCollapseAllBtn(e);
  addStdCDropdown(e);

  let btn5 = createCollapseByName();
  e.append(btn5);

  e.append(createFontSizeDropdown());

  document.getElementsByClassName("content-wrapper")[0].prepend(e);
  
  // Adds click effects here

  $('#show-idx-button').click(function(){
    $(this).toggleClass("active");
    $(".calltree-idx").toggleClass("hidden");
  });

  $("#expand-all-button").click(function(){
    $(".calltree-line-wrapper").each(function( index ) {
      if(!$(this).hasClass("open")) {
        $(this).addClass("open");
      }
      $(".coverage-line-inner.expand-symbol").toggleClass("collapse-symbol expand-symbol");
    });
  })

  $("#collapse-all-button").click(function(){
    $(".calltree-line-wrapper").each(function( index ) {
      if($(this).hasClass("open")) {
        $(this).removeClass("open");
      }
      $(".coverage-line-inner.collapse-symbol").toggleClass("collapse-symbol expand-symbol");
    });
  })

  $(".fontsize-option").click(function(){
    var selectedFontSize=$(this).data("fontsize");
    $(".coverage-line-inner").css("font-size", selectedFontSize);
    $(".fontsize-option").removeClass("active");
    $(this).addClass("active");
  })
}

// Returns an array of function names that are collapsible
function getCollapsibleFunctions() {
  let ctNodes = document.getElementsByClassName("coverage-line-inner collapse-symbol");
  let funcList = [];
  for(var i=0;i<ctNodes.length;i++) {
    if(ctNodes[i].querySelector(".language-clike")===undefined) {
      continue
    }
    let funcName = ctNodes[i].querySelector(".language-clike").innerText.trim();
    if(!funcList.includes(funcName)) {
      funcList.push(funcName)
    }
  }
  return funcList.sort();
}

// Adds collapsible functions to the dropdown
function addCollapsibleFunctionsToDropdown() {
  var collapseByNameDropdown = document.getElementById("collapseByNameDropdown");
  let funcNames = getCollapsibleFunctions();
  for(var i=0;i<funcNames.length;i++) {
    let listItem = document.createElement("div");
    listItem.classList.add("checkbox-line-wrapper");
    listItem.classList.add("collapse-function-with-name");
    listItem.style.display = "block"
    listItem.innerText = funcNames[i];
    collapseByNameDropdown.append(listItem)
  }
}

function createCollapseByName() {
  let btn4 = document.createElement("span");
  btn4.classList.add("calltree-nav-btn2");
  btn4.id = "collapse-by-name";
  var htmlString = "";
  htmlString += `<div class="dropdown">
    <button onclick="displayCollapseByName()" class="dropbtn collapse-by-name-dropdown">Collapse by name</button>
    <div id="collapseByNameDropdown" class="dropdown-content coll-by-name" style="max-height: 500px; overflow-y: scroll">`          
  htmlString += `</div>
  </div>`;
  btn4.innerHTML = htmlString;
  return btn4;
}

// Adds the back button to the nav bar
function addBackButton(parentElement) {
  let backBtn = document.createElement("a");
  backBtn.style.marginRight = "10px";
  backBtn.style.textDecoration = "none";
  backBtn.href = "fuzz_report.html"
  let backBtnInner = document.createElement("span");
  backBtnInner.classList.add("calltree-nav-btn");
  backBtnInner.innerText = "< Back to report";
  backBtn.prepend(backBtnInner);
  parentElement.prepend(backBtn);
}

// Adds the show-idx btn to "parentElement"
function addShowIdxButton(parentElement) {  
  let btn = document.createElement("span");
  btn.classList.add("calltree-nav-btn");
  btn.classList.add("active");
  btn.id = "show-idx-button"
  btn.innerText = "show idx";
  parentElement.append(btn);
}

// Adds the expand all btn to "parentElement"
function addExpandAllBtn(parentElement) {
  let btn = document.createElement("span");
  btn.classList.add("calltree-nav-btn");
  btn.id = "expand-all-button"
  btn.innerText = "Expand all";
  parentElement.append(btn);
}

// Adds the collapse all btn to "parentElement"
function addCollapseAllBtn(parentElement) {
  let btn = document.createElement("span");
  btn.classList.add("calltree-nav-btn");
  btn.id = "collapse-all-button"
  btn.innerText = "Collapse all";
  parentElement.append(btn);  
}

// Adds the std c dropdown to "parentElement"
function addStdCDropdown(parentElement) {
  let btn = createStdCDropdown();
  parentElement.append(btn);
}

function createStdCDropdown() {
  let btn4 = document.createElement("span");
  btn4.classList.add("calltree-nav-btn2");
  btn4.id = "std-lib-functions";

  // Create the html
  var dropDownHtml = `<div class="dropdown">
    <button onclick="displayNavBar()" class="dropbtn std-c-func-list">Std C funcs</button>
    <div id="myDropdown" class="dropdown-content stdlibc">`
  
  var funcNames = ["free", "abort", "malloc", "calloc", "exit", "memcmp", "strlen"]
  for(var i=0;i<funcNames.length;i++) {
    var funcName = funcNames[i];
    dropDownHtml += `<div style="display:flex" class="checkbox-line-wrapper">
        <div style="flex:1"><input type="checkbox" name="${funcName}-chckbox" id="${funcName}-chckbox" class="shown-checkbox" checked></div>
        <div style="flex:3">${funcName}</div>
      </div>`
  }

  // Close the html
  dropDownHtml += "</div></div>";
  btn4.innerHTML = dropDownHtml;
  return btn4;
}

function addNavbarClickEffects() {
  // std c funcs dropdown
  // Close the dropdown menu if the user clicks outside of it
  window.onclick = function(event) {
    if (!event.target.matches(['.std-c-func-list','.font-size-dropdown', '.collapse-by-name-dropdown'])) {
      var stdCDropdown = document.getElementById("myDropdown");
      if(stdCDropdown.classList.contains("show")) {
        stdCDropdown.classList.remove("show");
      }

      var fontSize = document.getElementById("fontSizeDropdown");
      if(fontSize.classList.contains("show")) {
        fontSize.classList.remove("show");
      }

      var fontSize = document.getElementById("collapseByNameDropdown");
      if(fontSize.classList.contains("show")) {
        fontSize.classList.remove("show");
      }
    } else if(event.target.matches('.std-c-func-list')) {
      hideDropdown("collapseByNameDropdown");
      hideDropdown("fontSizeDropdown");
    } else if(event.target.matches('.font-size-dropdown')) {
      hideDropdown("collapseByNameDropdown");
      hideDropdown("myDropdown");
    } else if(event.target.matches('.collapse-by-name-dropdown')) {
      hideDropdown("fontSizeDropdown");
      hideDropdown("myDropdown");

    }
  }
}

function hideDropdown(dropdownId) {
  var stdCDropdown = document.getElementById(dropdownId);
  if(stdCDropdown.classList.contains("show")) {
    stdCDropdown.classList.remove("show");
  }
}

function hideNodesWithText(text) {
  $(".coverage-line-inner").each(function( index ) {
    var funcName = $( this ).find(".language-clike").text().trim()
    if(funcName===text) {
      $(this).toggleClass("hidden");
    }
  });
}

function addExpandSymbols() {
  $( ".coverage-line-inner").each(function( index ) {
    var numberOfSubNodes = $(this).closest(".coverage-line").find(".coverage-line-inner").length
    if(numberOfSubNodes>1) {
      $(this).addClass("collapse-symbol");
    }
  });
}

function createFontSizeDropdown() {
  let btn = document.createElement("span");
  btn.classList.add("calltree-nav-btn2");
  btn.id = "font-size-dropdown-btn";
  btn.innerHTML = `<div class="dropdown ">
    <button onclick="displayFontSizeDropdown()" id="font-size-dropdown-btn2" class="dropbtn font-size-dropdown">Fontsize</button>
    <div id="fontSizeDropdown" class="dropdown-content fontsize">
      <div>
        <div style="display:block" class="fontsize-option" data-fontsize="10px">10</div>
        <div style="display:block" class="fontsize-option" data-fontsize="11px">11</div>
        <div style="display:block" class="fontsize-option" data-fontsize="12px">12</div>
        <div style="display:block" class="fontsize-option" data-fontsize="13px">13</div>
        <div style="display:block" class="fontsize-option active" data-fontsize="14px">14</div>
        <div style="display:block" class="fontsize-option" data-fontsize="15px">15</div>
        <div style="display:block" class="fontsize-option" data-fontsize="16px">16</div>
      </div>
    </div>
  </div>`;
  return btn
}