// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

function sortTable(item, colName, conv) {
	table = item.parentNode.parentNode.parentNode;
	rows = table.getElementsByTagName("tr");
	col = findColumnByName(rows[0].getElementsByTagName("th"), colName);
	values = new Array;
	for (i = 1; i < rows.length; i++)
		values[i] = conv(rows[i].getElementsByTagName("td")[col].textContent);
	desc = isSorted(values);
	do {
		changed = false;
		for (i = 1; i < values.length - 1; i++) {
			v0 = values[i];
			v1 = values[i + 1];
			if (desc && v0 >= v1 || !desc && v0 <= v1)
				continue;
			changed = true;
			values[i] = v1;
			values[i + 1] = v0;
			rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
		}
	} while (changed);
	return false;
}

function findColumnByName(headers, colName) {
	for (i = 0; i < headers.length; i++) {
		if (headers[i].textContent == colName)
			return i;
	}
	return 0;
}

function isSorted(values) {
	for (i = 1; i < rows.length - 1; i++) {
		if (values[i] > values[i + 1])
			return false;
	}
	return true;
}

function textSort(v) { return v.toLowerCase(); }
function numSort(v) { return -parseInt(v); }
function reproSort(v) { return v == "C" ? 0 : v == "syz" ? 1 : 2; }
function patchedSort(v) { return v == "" ? -1 : parseInt(v); }

function timeSort(v) {
	if (v == "now")
		return 0;
	m = v.indexOf('m');
	h = v.indexOf('h');
	d = v.indexOf('d');
	if (m > 0 && h < 0)
		return parseInt(v);
	if (h > 0 && m > 0)
		return parseInt(v) * 60 + parseInt(v.substring(h + 1));
	if (d > 0 && h > 0)
		return parseInt(v) * 60 * 24 + parseInt(v.substring(d + 1)) * 60;
	if (d > 0)
		return parseInt(v) * 60 * 24;
	return 1000000000;
}
