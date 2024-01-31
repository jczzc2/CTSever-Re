if __name__=='__main__':
    choice=input('sever/client>>')
    match choice:
        case 's':
            import sever
            sever.main()
        case 'c':
            import client
            client.main()
        case 'sever':
            import sever
            sever.main()
        case 'client':
            import client
            client.main()
        case 'sev':
            import sever
            sever.main()
        case 'cli':
            import client
            client.main()
