if __name__ == '__main__':
    type=int(input("enter type of cipher\n1.Caesar\n2.Multiplicative\n: "))
    message=input("enter message: ")
    choice= int(input("enter choice\n1.Encrypt\n2.Decrypt\n: "))
    key= int(input("enter the key: "))
    charList=list(message)
    if type==1:
        if choice==1:
            for i in range(len(charList)):
                if charList[i]==' ':
                    continue
                charList[i]=chr(((ord(charList[i])-ord('a')+key)%26)+ord('a'))
            print("".join(charList))
        elif choice==2:
            for i in range(len(charList)):
                if charList[i] == ' ':
                    continue
                charList[i]=chr(((ord(charList[i])-ord('a')-key)%26)+ord('a'))
            print("".join(charList))

    elif type==2:
        if choice==1:
            for i in range(len(charList)):
                if charList[i]==' ':
                    continue
                charList[i]=chr((((ord(charList[i])-ord('a'))*key)%26)+ord('a'))
            print("".join(charList))
        elif choice==2:
            invKey=1
            while(key*invKey)%26!=1:
                invKey+=1
            for i in range(len(charList)):
                if charList[i] == ' ':
                    continue
                charList[i]=chr((((ord(charList[i])-ord('a'))*invKey)%26)+ord('a'))
            print("".join(charList))