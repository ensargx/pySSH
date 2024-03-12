from pyssh import pySSH
import os
import time
import threading
from random import randint

hostkey_path = os.path.join(os.path.expanduser('~'), 'keys')

app = pySSH(
    hostkey_path = hostkey_path
)

@app.client
class Client:
    all_players = []
    def __init__(self, send, recv, username, terminal):
        self.send = send
        self.recv = recv
        self.terminal = terminal
        self.username = username
        self.snake_len = 0
        self.snake = [(0, 0)]
        self.food = (5, 5)
        self.direction = (1, 0)
        self.tmp_dir = (1, 0)
        self.isPlaying = True
        self.all_players.append(self)

        # start game thread
        self.game_thread = threading.Thread(target=self.run)
        self.game_thread.start()

    def handler(self, data):
        if data == b'\x1b[A': # up
            self.direction = (0, -1)
        elif data == b'\x1b[B': # down
            self.direction = (0, 1)
        elif data == b'\x1b[C': # right
            self.direction = (1, 0)
        elif data == b'\x1b[D': # left
            self.direction = (-1, 0)
        elif data == b' ': # space
            if self.direction == (0, 0):
                self.direction = self.tmp_dir
            else:
                self.tmp_dir = self.direction
                self.direction = (0, 0)
        elif data == b'\x03': # Ctrl+C
            self.send(b'Goodbye!')
            self.isPlaying = False

    def move(self):
        x, y = self.snake[0]
        # if snake eats food
        if (x + self.direction[0], y + self.direction[1]) == self.food:
            self.snake_len += 1
            # generate new food
            self.food = randint(0, 10), randint(0, 10)

        # move snake
        x += self.direction[0]
        y += self.direction[1]
        self.snake.insert(0, (x, y))
        if len(self.snake) > self.snake_len:
            self.snake.pop()

    def draw(self):
        # clear screen
        self.send(b'\x1b[2J')
        # draw snake
        for x, y in self.snake:
            self.send(b'\x1b[' + str(y).encode() + b';' + str(x).encode() + b'H*')
        # draw food
        x, y = self.food
        self.send(b'\x1b[' + str(y).encode() + b';' + str(x).encode() + b'H#')
        # draw score top right
        for i, player in enumerate(self.all_players):
            # move cursor to top right + i line
            self.send(b'\x1b[' + str(i).encode() + b';10H' + player.username + b': ' + str(player.snake_len).encode())

    def run(self):
        # thread for sending data to client
        while self.isPlaying:
            self.move()
            self.draw()
            time.sleep(0.1)

if __name__ == '__main__':
    app.run(port=2222)
