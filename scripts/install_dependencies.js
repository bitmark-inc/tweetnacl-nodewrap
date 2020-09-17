var exec = require('child_process').exec;

if (process.platform !== "win32") {
	console.log("run install for MAC or Linux OS ==================");
	function puts(error, stdout, stderr) {
		console.log(stdout);
	}
	exec("./check_installation.sh", puts);
}