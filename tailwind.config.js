module.exports = {
  content: [
    "./internal/web/templates/**/*.html",
    "./internal/web/render.go"
  ],
  theme: {
    extend: {
      maxWidth: {
        shell: "1700px"
      },
      gridTemplateColumns: {
        filters: "minmax(0, 1fr) 220px 220px"
      },
      minWidth: {
        "finding-id": "13rem",
        "finding-title": "28rem"
      }
    }
  },
  plugins: []
};
