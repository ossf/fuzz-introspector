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
      console.log("len of elems: ", $(this).find(".calltree-line-wrapper."+nextLevel).length)
      $(this).closest(".coverage-line").find(".calltree-line-wrapper."+nextLevel).toggleClass("open");
      if($(this).hasClass("expand-symbol")) {
        $(this).removeClass("expand-symbol");
        $(this).addClass("collapse-symbol");
      }else if($(this).hasClass("collapse-symbol")) {
        $(this).removeClass("collapse-symbol");
        $(this).addClass("expand-symbol");
      }
  });
    createNavBar();
    addFuzzBlockerLines();
    addExpandSymbols();

    document.addEventListener('click', function(e) {
      e = e || window.event;
      var target = e.target;
      var menuElement = document.getElementById("std-lib-functions");
      if(isDescendant(menuElement, target)) {
         e.stopPropagation();
      }
  }, false);



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
});


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

function createNavBar() {
    let e = document.createElement("div");
    e.classList.add("calltree-navbar");

    let backBtn = document.createElement("a");
    backBtn.style.marginRight = "10px";
    backBtn.href = "/fuzz_report.html"
    let backBtnInner = document.createElement("span");
    backBtnInner.classList.add("calltree-nav-btn");
    backBtnInner.innerText = "<- Back to report";
    backBtn.prepend(backBtnInner);
    e.prepend(backBtn);


    let btn1 = document.createElement("span");
    btn1.classList.add("calltree-nav-btn");
    btn1.classList.add("active");
    btn1.id = "show-idx-button"
    btn1.innerText = "show idx";
    e.append(btn1);

    let btn2 = document.createElement("span");
    btn2.classList.add("calltree-nav-btn");
    btn2.id = "expand-all-button"
    btn2.innerText = "Expand all";
    e.append(btn2);

    let btn3 = document.createElement("span");
    btn3.classList.add("calltree-nav-btn");
    btn3.id = "collapse-all-button"
    btn3.innerText = "Collapse all";
    e.append(btn3);

    let btn4 = document.createElement("span");
    btn4.classList.add("calltree-nav-btn2");
    btn4.id = "std-lib-functions";
    btn4.innerHTML = `<div class="dropdown">
      <button onclick="displayNavBar()" class="dropbtn">Std C funcs</button>
      <div id="myDropdown" class="dropdown-content">
        <div style="display:flex">
          <div style="flex:1"><input type="checkbox" name="free-chckbox" id="free-chckbox" class="shown-checkbox" checked></div>
          <div style="flex:3">free</div>
        </div>
        <div style="display:flex">
          <div style="flex:1"><input type="checkbox" name="abort-chckbox" id="abort-chckbox" class="shown-checkbox" checked></div>
          <div style="flex:3">abort</div>
        </div>
        <div style="display:flex">
          <div style="flex:1"><input type="checkbox" name="malloc-chckbox" id="malloc-chckbox" class="shown-checkbox" checked></div>
          <div style="flex:3">malloc</div>
        </div>
        <div style="display:flex">
          <div style="flex:1"><input type="checkbox" name="calloc-chckbox" id="calloc-chckbox" class="shown-checkbox" checked></div>
          <div style="flex:3">calloc</div>
        </div>
        <div style="display:flex">
          <div style="flex:1"><input type="checkbox" name="exit-chckbox" id="exit-chckbox" class="shown-checkbox" checked></div>
          <div style="flex:3">exit</div>
        </div>
        <div style="display:flex">
          <div style="flex:1"><input type="checkbox" name="memcmp-chckbox" id="memcmp-chckbox" class="shown-checkbox" checked></div>
          <div style="flex:3">memcmp</div>
        </div>
        <div style="display:flex">
          <div style="flex:1"><input type="checkbox" name="strlen-chckbox" id="strlen-chckbox" class="shown-checkbox" checked></div>
          <div style="flex:3">strlen</div>
        </div>
      </div>
    </div>`;
    e.append(btn4);

    document.getElementsByClassName("content-wrapper")[0].prepend(e);

    

    // Close the dropdown menu if the user clicks outside of it
    window.onclick = function(event) {
      if (!event.target.matches('.dropbtn')) {
        var dropdowns = document.getElementsByClassName("dropdown-content");
        var i;
        for (i = 0; i < dropdowns.length; i++) {
          var openDropdown = dropdowns[i];
          if (openDropdown.classList.contains('show')) {
            openDropdown.classList.remove('show');
          }
        }
      }
    }
    

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