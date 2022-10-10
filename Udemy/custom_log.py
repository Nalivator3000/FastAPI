def log(tag='', message=''):
    with open('log.txt', 'a+') as log:
        log.write(f'{tag}: {message}\n')