/** Snippets from SAML-supporting Controller object for Project Management. **/

// ================================================================================================== //
i2b2.PM.doLogin = function() {
	i2b2.PM.model.shrine_domain = false;
	var input_errors = false;
	// change the cursor
	// show on GUI that work is being done
	i2b2.h.LoadingMask.show();
	
	// copy the selected domain info into our main data model
	var e = 'The following problems were encountered:';
	var val = i2b2.PM.udlogin.inputUser.value;
	if (!val.blank()) {
		var login_username = val.toLowerCase();
	} else {
		e += "\n  Username is empty";
		input_errors = true;
	}
	
	var val = i2b2.PM.udlogin.inputPass.value;
	if (!val.blank()) {
		var login_password = val;
				
	} else if (login_username.indexOf("@mgh.harvard.edu") >=0 || login_username.indexOf("@partners.org") >=0 ) {
		var login_password = '';								
				
	} else {
		e += "\n  Password is empty";
		input_errors = true;
	}
	i2b2.h.LoadingMask.show();

	if ((login_username.indexOf("@partners.org") >= 0 || login_username.indexOf("@mgh.harvard.edu") >= 0) && login_password =='') {
		<!-- Partners Okta Login -->	
		window.location.href = "URL-for-Partners-SAML-IDP";	
	} else {
		<!-- i2b2 login -->
		var p = i2b2.PM.udlogin.inputDomain;
		var val = p.options[p.selectedIndex].value;
		if (!val.blank()) {
			var p = i2b2.PM.model.Domains;
			if (p[val]) {
				
				// copy information from the domain record
				var login_domain = p[val].domain;
				
				var login_url = p[val].urlCellPM;
				i2b2.PM.model.url = login_url;
				var shrine_domain = Boolean.parseTo(p[val].isSHRINE);
				var login_project = p[val].project;
				
				if (p[val].debug != undefined) {
					i2b2.PM.model.login_debugging = Boolean.parseTo(p[val].debug);
				} else {
					i2b2.PM.model.login_debugging = false;
				}
				if (p[val].allowAnalysis != undefined) {
					i2b2.PM.model.allow_analysis = Boolean.parseTo(p[val].allowAnalysis);
				} else {
					i2b2.PM.model.allow_analysis = true;
				}
				if (p[val].adminOnly != undefined) {
					i2b2.PM.model.admin_only = Boolean.parseTo(p[val].adminOnly);
				} else {
					i2b2.PM.model.admin_only = false;
				}
				if (typeof p[val].installer !== undefined) {
					i2b2.PM.model.installer_path = p[val].installer;
				} 
				
			}
		} else {
			e += "\n  No login channel was selected";
		}
	
		// call the PM Cell's communicator Object
		var callback = new i2b2_scopedCallback(i2b2.PM._processUserConfig, i2b2.PM);
		var parameters = {
			domain: login_domain, 
			is_shrine: shrine_domain,
			project: login_project,
			username: login_username,
			password_text: login_password
		};
		var transportOptions = {
			url: login_url,
			user: login_username,
			password: login_password,
			domain: login_domain,
			project: login_project
		};
		
		if(!input_errors){
			i2b2.PM.ajax.getUserAuth("PM:Login", parameters, callback, transportOptions);
			} else {
			alert(e);
		}
	}
	
}
