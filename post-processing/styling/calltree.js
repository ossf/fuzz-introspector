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
  });

    let e = document.createElement("div");
    e.classList.add("calltree-navbar")

    let btn1 = document.createElement("span");
    btn1.classList.add("calltree-nav-btn");
    btn1.classList.add("active");
    btn1.innerText = "show idx";
    e.prepend(btn1);
    document.getElementsByClassName("content-wrapper")[0].prepend(e);

    $('.calltree-nav-btn').click(function(){
      $(this).toggleClass("active");
      $(".calltree-idx").toggleClass("hidden");
    });
    
});
