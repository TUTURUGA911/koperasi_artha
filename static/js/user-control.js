const togglePasswordOld = document.querySelector("#togglePasswordOld");
const passwordOld = document.querySelector("#old-password");

togglePasswordOld.addEventListener("click", function () {
    const type = passwordOld.getAttribute("type") === "password" ? "text" : "password";
    passwordOld.setAttribute("type", type);
    this.classList.toggle("bi-eye");
});

const togglePasswordNew = document.querySelector("#togglePasswordNew");
const passwordNew = document.querySelector("#new-password");

togglePasswordNew.addEventListener("click", function () {
    const type = passwordNew.getAttribute("type") === "password" ? "text" : "password";
    passwordNew.setAttribute("type", type);
    this.classList.toggle("bi-eye");
});

function is_email(asValue) {
    var regExp = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;
    return regExp.test(asValue);
}

function is_phone(asValue) {
    var regExp = /^\+62[0-9]{10,12}$/;
    return regExp.test(asValue);
}

function update_profile() {
    let inputFullname = $('#fullname');
    let inputEmail = $('#email');
    let inputJob = $('#job');
    let inputPhone = $('#mobile');
    let inputAddress = $('#address');
    let inputBio = $('#bio');
    
    let fullname = inputFullname.val();
    let email = inputEmail.val();
    let job = inputJob.val();
    let phone = inputPhone.val();
    let address = inputAddress.val();
    let bio = inputBio.val();
    let file = $("#image")[0].files[0];

    let helpFullname = $('#help-fullname');
    let helpEmail = $('#help-email');
    let helpJob = $('#help-job');
    let helpPhone = $('#help-phone');
    let helpAddress = $('#help-address');
    let helpBio = $('#help-bio');

    // Reset pesan sebelumnya
    $('.form-group').removeClass('mb-1').addClass('mb-3');
    helpFullname.text('').removeClass('text-danger text-success');
    helpEmail.text('').removeClass('text-danger text-success');
    helpJob.text('').removeClass('text-danger text-success');
    helpPhone.text('').removeClass('text-danger text-success');
    helpAddress.text('').removeClass('text-danger text-success');
    helpBio.text('').removeClass('text-danger text-success');

    if (fullname === "") {
        $('#fg-fullname').removeClass('mb-3').addClass('mb-1');
        helpFullname.text("Mohon masukkan nama lengkap anda!").addClass("text-danger");
        inputFullname.focus();
        return;
    }

    if (email === "") {
        $('#fg-email').removeClass('mb-3').addClass('mb-1');
        helpEmail.text("Mohon masukkan email!").addClass("text-danger");
        inputEmail.focus();
        return;
    } else if (!is_email(email)) {
        $('#fg-email').removeClass('mb-3').addClass('mb-1');
        helpEmail.text("Masukkan email dengan benar (contoh@contoh.com)").addClass("text-danger");
        inputEmail.focus();
        return;
    }

    if (job === "") {
        $('#fg-job').removeClass('mb-3').addClass('mb-1');
        helpJob.text("Mohon masukkan pekerjaan anda dengan benar!").addClass("text-danger");
        inputJob.focus();
        return;
    }

    if (phone === "") {
        $('#fg-phone').removeClass('mb-3').addClass('mb-1');
        helpPhone.text("Mohon masukkan nomor anda dengan benar!").addClass("text-danger");
        inputPhone.focus();
        return;
    } else if (!is_phone(phone)) {
        $('#fg-phone').removeClass('mb-3').addClass('mb-1');
        helpPhone.text("Masukkan nomor telepon antara 11-13 digit dan diawali dengan +62").addClass("text-danger");
        inputPhone.focus();
        return;
    }

    if (address === "") {
        $('#fg-address').removeClass('mb-3').addClass('mb-1');
        helpAddress.text("Mohon masukkan alamat anda dengan benar!").addClass("text-danger");
        inputAddress.focus();
        return;
    }

    if (bio === "") {
        $('#fg-bio').removeClass('mb-3').addClass('mb-1');
        helpBio.text("Mohon masukkan bio profil anda dengan benar!").addClass("text-danger");
        inputBio.focus();
        return;
    }

    let form_data = new FormData();
    if (file) {
        form_data.append("file_give", file);
    }
    form_data.append("fullname_give", fullname);
    form_data.append("email_give", email);
    form_data.append("job_give", job);
    form_data.append("phone_give", phone);
    form_data.append("address_give", address);
    form_data.append("bio_give", bio);

    $.ajax({
        type: "POST",
        url: "/update_profile",
        data: form_data,
        cache: false,
        contentType: false,
        processData: false,
        success: function (response) {
            if (response['result'] === 'success') {
                Swal.fire({
                    title: 'Berhasil!',
                    text: response['msg'],
                    icon: 'success',
                    confirmButtonText: 'OK'
                }).then(() => {
                    window.location.reload();
                });
            } else {
                Swal.fire({
                    title: 'Gagal!',
                    text: response['msg'],
                    icon: 'error',
                    confirmButtonText: 'OK'
                });
            }
        },
        error: function (xhr, status, error) {
            Swal.fire({
                title: 'Error!',
                text: 'Terjadi kesalahan saat memperbarui profil.',
                icon: 'error',
                confirmButtonText: 'OK'
            });
        }
    });
}

function resetPass(username) {
    let passOldInput = $('#old-password');
    let passNewInput = $('#new-password');

    let passOld = passOldInput.val().trim();
    let passNew = passNewInput.val().trim();

    // Validasi input di frontend
    if (passOld === '') {
        Swal.fire({
            title: 'Error!',
            text: 'Mohon masukkan kata sandi lama!',
            icon: 'error',
            confirmButtonText: 'OK'
        });
        passOldInput.focus();
        return;
    }

    if (passNew === '') {
        Swal.fire({
            title: 'Error!',
            text: 'Mohon masukkan kata sandi baru!',
            icon: 'error',
            confirmButtonText: 'OK'
        });
        passNewInput.focus();
        return;
    }

    // Validasi format kata sandi baru
    let passwordRegex = /^(?=.*\d)(?=.*[a-zA-Z])[0-9a-zA-Z!@#$%^&*]{8,20}$/;
    if (!passwordRegex.test(passNew)) {
        Swal.fire({
            title: 'Error!',
            text: 'Kata sandi baru harus 8-20 karakter, mengandung huruf dan angka!',
            icon: 'error',
            confirmButtonText: 'OK'
        });
        passNewInput.focus();
        return;
    }

    $.ajax({
        type: "POST",
        url: "/reset_pass",
        data: {
            username_give: username,
            old_password_give: passOld,
            passnew_give: passNew
        },
        success: function (response) {
            if (response['result'] === 'success') {
                Swal.fire({
                    title: 'Berhasil!',
                    text: response['msg'],
                    icon: 'success',
                    confirmButtonText: 'OK'
                }).then(() => {
                    passOldInput.val("");
                    passNewInput.val("");
                    window.location.reload();
                });
            } else {
                Swal.fire({
                    title: 'Gagal!',
                    text: response['msg'],
                    icon: 'error',
                    confirmButtonText: 'OK'
                });
                passOldInput.val("");
                passNewInput.val("");
                passOldInput.focus();
            }
        },
        error: function (xhr, status, error) {
            Swal.fire({
                title: 'Error!',
                text: 'Terjadi kesalahan saat memperbarui kata sandi: ' + error,
                icon: 'error',
                confirmButtonText: 'OK'
            });
            passOldInput.val("");
            passNewInput.val("");
            passOldInput.focus();
        }
    });
}