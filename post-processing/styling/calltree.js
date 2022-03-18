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
      $(this).toggleClass("expand-symbol collapse-symbol");
  });
    createNavBar();
    addExpandSymbols();

    
    
});

function createNavBar() {
    let e = document.createElement("div");
    e.classList.add("calltree-navbar")

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
    document.getElementsByClassName("content-wrapper")[0].prepend(e);

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

function addExpandSymbols() {
  $( ".coverage-line-inner").each(function( index ) {
    var numberOfSubNodes = $(this).closest(".coverage-line").find(".coverage-line-inner").length
    if(numberOfSubNodes>1) {
      $(this).addClass("collapse-symbol");
    }
  });
}