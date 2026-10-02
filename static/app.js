/* =========================================================
   NEON CURSOR FOLLOW EFFECT
========================================================= */

const cursorGlow = document.querySelector(".cursor-glow");

document.addEventListener("mousemove", function (event) {

    document.documentElement.style.setProperty(
        "--mouse-x",
        event.clientX + "px"
    );

    document.documentElement.style.setProperty(
        "--mouse-y",
        event.clientY + "px"
    );

});


/* =========================================================
   BUTTON GLOW
========================================================= */

const buttons = document.querySelectorAll(
    ".analyze-button"
);

buttons.forEach(function (button) {

    button.addEventListener("mousemove", function (event) {

        const rect = button.getBoundingClientRect();

        const x =
            event.clientX - rect.left;

        const y =
            event.clientY - rect.top;

        button.style.background =
            `radial-gradient(
                circle at ${x}px ${y}px,
                rgba(0, 174, 255, 0.22),
                rgba(0, 80, 150, 0.08)
            )`;

    });

    button.addEventListener("mouseleave", function () {

        button.style.background =
            "linear-gradient(90deg, rgba(0, 100, 255, 0.12), rgba(0, 200, 255, 0.08))";

    });

});


/* =========================================================
   CARD MOUSE GLOW
========================================================= */

const cards = document.querySelectorAll(
    ".stat-card, .analysis-card, .graph-node"
);

cards.forEach(function (card) {

    card.addEventListener("mousemove", function (event) {

        const rect = card.getBoundingClientRect();

        const x =
            event.clientX - rect.left;

        const y =
            event.clientY - rect.top;

        card.style.background =
            `radial-gradient(
                circle at ${x}px ${y}px,
                rgba(0, 174, 255, 0.08),
                #05080c 55%
            )`;

    });

    card.addEventListener("mouseleave", function () {

        card.style.background = "";

    });

});