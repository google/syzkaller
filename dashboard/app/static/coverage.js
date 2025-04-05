// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

$(document).ready(initTogglers);
$(document).ready(initUpdateForm);

// Initializes the file tree onClick collapse logic.
function initTogglers(){
  $(".caret").on("click", function() {
    $(this).toggleClass("caret-down");
    $(this).closest("li").find(".nested").first().toggleClass("active");
  });
}

function initUpdateForm(){
  $('#target-manager').change(function() {
    if ($(this).val() === '') { // selected "*"
      $("#unique-only").prop("checked", false);
      $('#unique-only').prop('disabled', true);
    } else {
      $('#unique-only').prop('disabled', false);
    }
  });

  var curUrlParams = new URLSearchParams(window.location.search);
  $('#target-period').val(curUrlParams.get('period'));
  if (curUrlParams.get('period_count') != null) {
    $('#target-period-count').val(curUrlParams.get('period_count'));
  }
  $('#target-subsystem').val(curUrlParams.get('subsystem'));
  $('#target-manager').val(curUrlParams.get('manager'));
  $("#unique-only").prop("checked", curUrlParams.get('unique-only') == "1");
  $('#unique-only').prop('disabled', $('#target-manager').val() == '');
}

// This handler is called when user clicks on the coverage percentage.
// It downloads the kernel file coverage html block and adjust page to show it.
// "#file-content-prev" and "#file-content-curr" are the file content <div>s.
// "#file-details-prev" and "#file-details-curr" are the corresponding <div>s used to show per-file details.
function onShowFileContent(url) {
  var curUrlParams = new URLSearchParams(window.location.search);
  url += '&subsystem=' + (curUrlParams.get('subsystem') || "")
  url += '&manager=' + (curUrlParams.get('manager') || "")
  url += '&unique-only=' + (curUrlParams.get('unique-only') || "")

  $.get(url, function(response) {
    $("#file-content-prev").html($("#file-content-curr").html());
    $("#file-content-curr").html(response);

    $("#file-details-prev").html($("#file-details-curr").html());
    // It looks hacky but costs nothing. Let's show all the url parameters as a source description.
    details = url.split("?")[1].split("&");
    $("#file-details-curr").html("Source information:\n" + details.join("\n"));
  });
}
