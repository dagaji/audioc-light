#!/bin/bash

gcc -Wall -Wextra -o build/audioc.o audiocArgs.c circularBuffer.c configureSndcard.c audioc_light.c
