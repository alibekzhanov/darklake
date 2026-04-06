document.addEventListener("DOMContentLoaded", function () {
    let lastScrollY = window.scrollY;
    const header = document.getElementById("header");
    const sidebar = document.getElementById("sidebar");
    const openSidebar = document.getElementById("open_sidebar");
    const closeSidebar = document.getElementById("close_sidebar");

    function handleScroll() {
        const currentScrollY = window.scrollY;

        if (currentScrollY > lastScrollY && currentScrollY > 50) {
            header.classList.add("hidden");
        } else {
            header.classList.remove("hidden");
        }

        lastScrollY = currentScrollY;
    }

    openSidebar.addEventListener("click", e => {
        e.preventDefault();
        sidebar.classList.add("open");
    });

    closeSidebar.addEventListener("click", e => {
        e.preventDefault();
        sidebar.classList.remove("open");
    });

    window.addEventListener("scroll", handleScroll);
});
