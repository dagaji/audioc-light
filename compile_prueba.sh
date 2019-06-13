#!/bin/bash

gcc -Wall -Wextra -o build/audioc_prueba.o audiocArgs.c circularBuffer.c configureSndcard.c audioc_light_prueba.c
