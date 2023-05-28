function copyUsername(username) {
  // Create a temporary textarea element to hold the username
  var tempTextarea = document.createElement('textarea');
  tempTextarea.value = username;
  document.body.appendChild(tempTextarea);

  // Select the contents of the textarea and copy it to clipboard
  tempTextarea.select();
  document.execCommand('copy');

  // Remove the temporary textarea element
  document.body.removeChild(tempTextarea);
  // Display a confirmation message (optional)
  //alert('Copied: ' + username); 

  // Hide the sign-out icon
  var signOutIcon = document.getElementsByTagName('i')[index];
  signOutIcon.style.display = 'none';

}

function submitForm(number) {
    const form = document.createElement('form');
    form.method = 'post';
    form.action = 'passworddel.php';
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'number';
    input.value = number;
    form.appendChild(input);
    document.body.appendChild(form);
    form.submit();
}

