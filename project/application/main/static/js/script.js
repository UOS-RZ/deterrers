addEventListener("hashchange", (event) => {
	const sort = window.location.hash
		.replace(/^#/, '')
		.split('&')
		.filter(x => x.match(/^sort:[0-9]*:.*sc$/))
		.map(x => x.split(':').slice(1));
	if (sort.length > 0) {
		const field = parseInt(sort[0][0]);
		const asc = sort[0][1] === 'asc';
		const hosts = document.getElementById('hosts');
		const head = hosts.getElementsByTagName('thead')[0];
		const sort_links = head.getElementsByTagName('a');
		for (let i = 0; i < sort_links.length; i++) {
			const order = (i === field && asc) ? 'desc' : 'asc';
			sort_links[i].href = `#sort:${i}:${order}`;
		}
		sort_hosts(field, asc)
	}
});

function compareIP(a, b) {
	a = a.trim().split('.').map(x => parseInt(x));
	b = b.trim().split('.').map(x => parseInt(x));
	return a.map((k, i) => [k, b[i]])
		.reduce((ret, val) => {return ret || Math.sign(val[0] - val[1])}, 0)
}

function sort_hosts(field, asc) {
	// sort table
	const hosts = document.getElementById('hosts');
	const body = hosts.getElementsByTagName('tbody')[0];
	const rows = Array.from(body.getElementsByTagName('tr'));
	const order = asc ? 1 : -1;
	rows.sort((row1, row2) => {
		const a = row1.getElementsByTagName('td')[field].innerText;
		const b = row2.getElementsByTagName('td')[field].innerText;
		return order * (field ? a.localeCompare(b) : compareIP(a, b));
	})
	body.textContent = '';
	for (const row of rows) {
		body.append(row);
	}
}

document.addEventListener('DOMContentLoaded', function() {
  
const gsm_status_list = document.querySelectorAll(".gsm-status-class");

gsm_status_list.forEach(gsm_status =>{

if (gsm_status.textContent == "Done") {
  gsm_status.style.backgroundColor = "#0f430f";
} else if (gsm_status.textContent == "Running")
{
  gsm_status.style.backgroundColor = "#680d0d";
} else {
  gsm_status.style.backgroundColor = "#585858";
  gsm_status.style.color = "white";
}
});

});
