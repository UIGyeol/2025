import time  
import os    

def clear_screen():

    os.system('cls' if os.name == 'nt' else 'clear')

def popscreen():

    for i in range(10, 0, -1): 
        clear_screen()  
        print(f'새해까지 {i}초')  
        time.sleep(1)
    print("Happy New Year!")

popscreen()
