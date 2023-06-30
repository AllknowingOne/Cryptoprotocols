# Cryptoprotocols
## LAB1
ГОСТ 34.12-18. Кузнечик.
Размер блока 128бит, длина ключа 256 бит, 10 раундов.<br>
Представляет из себя SP-сеть и сетью Фейстеля для генерации рааундовых ключей.

Шифр является устойчивым для всех видов атак на блочные шифры. Сложность полного перебора 2^{256}. Существуют атаки с вычислительной сложностью 2^{140}<br>

Шифр реализован в виде класса LSX. Ключ и ОТ подаются в виде соответствующим образом инициализированных std::vector<uint8_t><br>

Механизм очистки ключевой информации представлен простым занулением байтов и последующей проверкой if-ами на равенство нулю, чтобы предотвратить возможные оптимизации компилятора.<br>
Механизм контроля работоспособности заключается в прогоне тестового примера из ГОСТа в конструкторе класса.<br>
Механизм контроля целостности.<br>
Весь проект собирается, все файлы окончательно компилируются, линкуются и больше не меняются (не меняются так, чтобы не изменялись вызовы функций или их порядок). Для реализаций критических функций считается чексумма по набору опкодов, соответствующих этим функциям. Длина функций и соответствующие им наборы опкодов получаются детерминированно (в действительности компилятор не дает нам такую гарантию, но на практике так и происходит). Из скомпилированного бинаря берется реализация функции, считается чексумма по алгоритму crc32 и хранится в функции проверки (или конструкторе класса). В рантайме чексумма функции считается вновь, полученная в рантайме чексумма сравнивается с предпосчитанной ранее и если они не сходятся, то это означает, что злоумышленник патчил бинарь. Из минусов стоит отметить муторность такого метода. Для того, чтобы быстро считать чексуммы реализаций функций следует написать парсер. <br>

В случае провала проверок какого-то из механизмов контроля в соответствующий лог записываются сообщения с соответствующей ошибкой и временем ее возникновения.

Представлена реализация самого шифра и режима OMAC для него.
