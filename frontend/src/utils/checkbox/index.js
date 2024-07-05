export function clickCheckbox(item){
    item.cookieSelected +=1;
    if (item.cookieSelected == item.itemsLen) {
        item.allChecked = true;
    } else {
        item.allChecked = false;
    }
}

export function toggleSelection(item){
    var ischecked = document.getElementById("main-checkbox").checked;
    var checkboxes = document.getElementsByClassName("item-checkbox");
    [].forEach.call(checkboxes, function (checkbox) {
      checkbox.checked = ischecked;
    });
    if (ischecked) {
        item.cookieSelected = item.itemsLen;
        item.allChecked = true;
    } else {
        item.cookieSelected = 0;
        item.allChecked = false;
    }
}

export default {clickCheckbox, toggleSelection}