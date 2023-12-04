const socket = io();
let userName;
let room;

const joinRoom = () => {
  document.getElementById("field_main").style.display = "block";
  document.getElementById("field_room").style.display = "none";

  userName = document.getElementById("name").value;
  room = document.getElementById("room").value;
  socket.emit("join", { room });
};

const sendMessage = () => {
  const message = document.getElementById("message").value;
  socket.emit("message", { text: message, name: userName, room });
  document.getElementById("message").value = "";
};

socket.on("message", (data) => {
  const messageElement = document.createElement("div");
  messageElement.classList.add("message");
  messageElement.classList.add(
    data.name === userName ? "own-message" : "other-message"
  );

  if (data.name === userName) {
    messageElement.innerHTML = `${data.text}`;
  } else {
    messageElement.innerHTML = `<div class="nama_user">${data.name}</div><div>${data.text}</div>`;
  }

  document.getElementById("chat-box").appendChild(messageElement);
});
