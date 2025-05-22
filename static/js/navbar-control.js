function login_auth() {
  $.ajax({
    type: "GET",
    url: "/auth_login",
    data: {},
    success: function (response) {
      let currentUrl = window.location.pathname;
      let temp_navbar = "";

      if (response["result"] == "success") {
        // User is logged in
        temp_navbar = `
        <ul>
          <li><a href="/simpanan" id="navsimpanan" class="${currentUrl === '/simpanan' ? 'active' : ''}">Simpanan</a></li>
          <li><a href="/pinjaman" id="navpinjaman" class="${currentUrl === '/pinjaman' ? 'active' : ''}">Pinjaman</a></li>
          <li><a href="/cek-status" id="navcekstatus" class="${currentUrl === '/cek-status' ? 'active' : ''}">Cek Status</a></li>
          <li>
            <a onclick="sign_out()" style="cursor: pointer" id="navlogout" class="">
              Logout&nbsp;&nbsp;
              <img class="rounded-circle shadow-1-strong me-3" src="/static/${response.data.profile_icon}" alt="avatar" width="30" height="30" />
            </a>
          </li>
        </ul>`;
      } else {
        // User is not logged in
        temp_navbar = `
        <ul>
          <li><a href="/" id="navhome" class="${currentUrl === '/' ? 'active' : ''}">Beranda</a></li>
          <li><a href="/tentangkami" id="navabout" class="${currentUrl === '/tentangkami' ? 'active' : ''}">Tentang Kami</a></li>
          <li><a href="/layanan" class="${currentUrl === '/layanan' ? 'active' : ''}" href="/layanan">Layanan</a></li>
          <li><a href="/kontak" id="navmedia" class="${currentUrl === '/kontak' ? 'active' : ''}">Kontak</a></li>
          <li><a href="/login" id="navlogin">Login</a></li>
        </ul>`;
      }

      // Insert navbar into the element with id 'navbar'
      $("#navbar").html(temp_navbar);
    },
  });

  $(document).on("click", ".navbar .dropdown > a", function (e) {
    e.preventDefault(); // Prevent default navigation
    let parent = $(this).parent();

    // Close other dropdowns if any are open
    $(".navbar .dropdown").not(parent).removeClass("dropdown-active");

    // Toggle dropdown
    parent.toggleClass("dropdown-active");
  });
}

login_auth();

// Logout function remains the same
function sign_out() {
  Swal.fire({
    title: "Are you sure?",
    text: "Anda akan logout dari akun anda",
    icon: "warning",
    showCancelButton: true,
    confirmButtonColor: "#3085d6",
    cancelButtonColor: "#d33",
    confirmButtonText: "Ya, logout!",
  }).then((result) => {
    if (result.isConfirmed) {
      $.removeCookie("mytoken", { path: "/" });
      Swal.fire({
        title: "Ter-logout!",
        text: "Anda sudah logout dari akun anda!",
        icon: "warning",
      }).then((result) => {
        if (result.isConfirmed) {
          window.location.href = "/login";
        }
      });
    }
  });
}
