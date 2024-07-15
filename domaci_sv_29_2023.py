# OVE TRI METODE ĆE BITI POZIVANE KROZ AUTOMATSKE TESTOVE. NEMOJTE MENJATI NAZIV, PARAMETRE I POVRATNU VREDNOST.
#Dozvoljeno je implementirati dodatne, pomoćne metode, ali isključivo u okviru ovog modula.

from stack import Stack
from tokenizer import tokenize

# Funkcija proverava prioritete operacija, sto je veci prioritet, vraca veci broj
def precedence(op):
    if op == '+' or op == '-':
        return 1
    if op == '*' or op == '/':
        return 2
    if op == '`':
        return 3
    if op == '^':
        return 4
    if op == '(' or op == ')':
        return 0
    return -1

# Funkcija koja proverava da li je token operator
def isOperator(token):
    operators = set(['+', '-', '*', '/', '^', '`'])
    return token in operators

# Ako dodje do greske u izrazu, pozivamo ovaj izuzetak
class ExpressionError(Exception):
    pass

# Funckija za proveravanje da li je token broj, pokusava da ga pretvori u float, i ako moze vraca True, a u suprotnom False
def isNumber(token):
    try:
        float(token)
        return True
    except ValueError:
        return False

def infix_to_postfix(expression):
    """Funkcija konvertuje izraz iz infiksne u postfiksnu notaciju

    Args:
        expression (string): Izraz koji se parsira. Izraz može da sadrži cifre, zagrade, znakove računskih operacija.
        U slučaju da postoji problem sa formatom ili sadržajem izraza, potrebno je baciti odgovarajući izuzetak.

    Returns:
        list: Lista tokena koji predstavljaju izraz expression zapisan u postfiksnoj notaciji.
    Primer:
        ulaz '6.11 - 74 * 2' se pretvara u izlaz [6.11, 74, 2, '*', '-']
    """
    # Pocetni niz dovijamo iz tokenize funkcije, pravimo stek, listu za output i varijablu za brojanje otvorenih zagrada
    input = tokenize(expression)
    stack = Stack()
    output = []
    bracketsOpen = 0
    for i in range(len(input)):

        # Provaravamo da li su dva operatora jedan pored drugog, ako jesu jednacina je neispravna
        if i > 0 and isOperator(input[i]) and isOperator(input[i-1]):
            raise ExpressionError("Invalid expression, two operators are next to each other")

        # Proveravamo ako je token cifra, stavljamo ga u output, a pre toga proveravamo
        # da ispred njega nije jos jedna cifra ili zatvorena zagrada, jer bi onda jednacina bila neispravna
        if isNumber(input[i]):
            if (isNumber(input[i-1]) or input[i-1] == ')') and output:
                raise ExpressionError("Invalid expression, two numbers in a row")
            output.append(input[i])


        # Ako je token otvorena zagrada, stavljamo ga na stek i dodajemo 1 na varijablu koja broji otvorene zagrade
        elif input[i] == '(':
            stack.push(input[i])
            bracketsOpen += 1

        elif input[i] == ')':

            # Ako je zatvorena zagrada, proveravamo da li je pre nje bila otvorena zagrada, ako nije jednacina je neispravna
            if not bracketsOpen:
                raise ExpressionError("Invalid expression, bracket not open")
            
            # Ako su zagrade prazne, jednacina je neispravna
            elif stack.top() == '(':
                raise ExpressionError("Invalid expression, empty brackets")
            
            # Stavljamo u output sve operatore sa steka dok ne dodjemo do otvorene zagrade
            while not stack.is_empty() and stack.top() != '(':
                output.append(stack.pop())

            #Izbacujemo i tu otvorenu zagradu sa steka i oduzimamo 1 od varijable za otvorene zagrade
            if not stack.is_empty():
                stack.pop()
            bracketsOpen -= 1

        # Ako naidjemo na -, moramo da proverimo da li je taj minus unarni ili binarni
        elif input[i] == '-':

            # Ako je prethodni token cifra ili zatvorena zagrada, onda je binarni
            if output and (isNumber(input[i-1]) or input[i-1] == ')'):

                # Ako je operacija manjeg prioriteta od operacija na steku, izbacujemo ih sa steka i na kraju na stek stavljamo trenutnu operaciju
                while not stack.is_empty() and precedence(input[i]) <= precedence(stack.top()):
                    output.append(stack.pop())
                stack.push(input[i])

            # U suprotnom minus je unarni i takvog ga stavljamo na stek
            else:
                stack.push('`')

        # Za ostale operacije proces je isti kao i za minus
        else:
            while not stack.is_empty() and precedence(input[i]) <= precedence(stack.top()):
                output.append(stack.pop())
            stack.push(input[i])

    # Na kraju praznimo sve operacije koje su ostale na steku
    while not stack.is_empty():
        output.append(stack.pop())

    # Ako se desilo da je ostala zagrada na outputum jednacina je neispravna
    if '(' in output or ')' in output:
        raise ExpressionError("Invalid expression, bracket mismatch")

    return output


def calculate_postfix(token_list):
    """Funkcija izračunava vrednost izraza zapisanog u postfiksnoj notaciji

    Args:
        token_list (list): Lista tokena koja reprezentuje izraz koji se izračunava. Izraz može da sadrži cifre, zagrade,
         znakove računskih operacija.
        U slučaju da postoji problem sa brojem parametara, potrebno je baciti odgovarajući izuzetak.

    Returns:
        result: Broj koji reprezentuje konačnu vrednost izraza

    Primer:
        Ulaz [6.11, 74, 2, '*', '-'] se pretvara u izlaz -141.89
    """
    stack = Stack()
    for token in token_list:

        # Prolazimo kroz listu datu u postfiksnoj notaciji, i ako je token broj, stavimo ga na stek
        if isNumber(token):
            stack.push(token)

        # Ako je token unarni minus, proveravamo da li ima broj na steku, ako nema pravimo gresku, a
        # ako ima, pretvaramo ga u float i stavljamo negativnu vrednost toga na stek
        elif token == '`': 
            if len(stack) < 1:
                raise ExpressionError("Not enough operands")
            operand = float(stack.pop())
            stack.push(-operand)

        # Ako je bilo koja binarna operacija, proveravamo da li ima dovoljno brojeva na steku, ako 
        # ima pretvaramo ih u float, i u zavistnoti od operacije u listi, izvrsavamo odgovarajucu operaciju i stavljamo rezultat na stek
        else:
            if len(stack) < 2:
                raise ExpressionError("Not enough operands")
            operand2 = float(stack.pop())
            operand1 = float(stack.pop())
            if token == '+':
                stack.push(operand1 + operand2)
            elif token == '*':
                stack.push(operand1 * operand2)
            elif token == '-':
                stack.push(operand1 - operand2)
            elif token == '/':
                stack.push(operand1 / operand2)
            elif token == '^':
                stack.push(operand1 ** operand2)

    # Kada zavrsimo sa obradom, ako na steku postoji vise od jednog broja, znamo da je doslo do greske, jer treba da ostane samo krajnji rezultat
    if len(stack) != 1:
        raise ExpressionError("Too many operands")
    
    # Na kraju vracamo tu krajnju vrednost sa steka
    return stack.pop()

def calculate_infix(expression):
    """Funkcija izračunava vrednost izraza zapisanog u infiksnoj notaciji

    Args:
        expression (string): Izraz koji se parsira. Izraz može da sadrži cifre, zagrade, znakove računskih operacija.
        U slučaju da postoji problem sa formatom ili sadržajem izraza, potrebno je baciti odgovarajući izuzetak.

        U slučaju da postoji problem sa brojem parametara, potrebno je baciti odgovarajući izuzetak.
        

    Returns:
        result: Broj koji reprezentuje konačnu vrednost izraza

    Primer:
        Ulaz '6.11 - 74 * 2' se pretvara u izlaz -141.89
    """
    # Samo pozivamo prethodne dve funkcije
    return calculate_postfix(infix_to_postfix(expression))
    
if __name__ == '__main__':
    print(calculate_infix("-(-(-(-(-2+3))^2*(-4+5))^3-(-6+7)*(-8-9))^4-(-2+3)*(5-2)^3/(-4+2)+((-2+3)^2-4*(-5))/(-6 +2)*(-3^2)"))
