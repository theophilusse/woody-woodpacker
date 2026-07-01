#include <stdio.h>

void push(int n)
{
    printf("push %d\n", n);
}

int main()
{
    unsigned char *p = 0;

    while (p < (unsigned char *)1000)
    {
        // ZERO
        if (*p == 0x24)
        {
            if (p[1] == 0)
                push(1);
            p += 2;
            continue;
        }
        else if (*p == 0x80)
        {
            if (p[2] == 0)
                push(1);
            p += 3;
            continue;
        }
        else if (*p == 0x31)
        {
            if ((p[1] & 0x18) >> 3 == (p[1] & 3))
                push(0);
        }
        // SET
        else if (*p >= 0xB8 && *p <= 0xBF)
        {
            push(1);
            p += 5;
            continue;
        }
        else if (*p == 0x48 && p[1] == 0x8D && (p[2] & 7) == 4 && p[3] == 0x25)
        {
            push(0);
            p += 8;
            continue;
        }
        // INC
        else if ((*p == 0xFE || *p == 0xFF || (*p == 0x48 && p[1] == 0xFF)) && (p[1] & 0xF8) == 0xC0)
        {
            if (*p == 0x48 && p[1] == 0xFF)
                p += 3;
            else
                p += 2;
            push(1);
            continue;
        }
        else if (*p == 0x83 && (p[1] & 0xF8) == 0xF8)
        {
            push(0);
            p += 3;
            continue;
        }
        // DEC
        else if ((*p == 0xFE || *p == 0xFF || (*p == 0x48 && p[1] == 0xFF)) && (p[1] & 0xF8) == 0xC8)
        {
            if (*p == 0x48 && p[1] == 0xFF)
                p += 3;
            else
                p += 2;
            push(1);
            continue;
        }
        else if (*p == 0x83 && (p[1] & 0xF8) == 0xE8 && p[2] == 1)
        {
            push(0);
            p += 3;
            continue;
        }
        else
            p++;
    }
    return 0;
}