*******************************************
*  Komodo 5.1r2 MP for Windows and Linux  *
*******************************************

Komodo 5.1 is an improvement over Komodo 5 and in addition supports
multi-core computers!  Komodo 5.1r2 is a bug fix release and
henceforth will be referred to as Komodo 5.1.  At the end of this
document we document the bug fixes and changes.

Some features in Komodo 5.1 MP:

 - multi-core support! 
 - automatic SSE4.2 detection
 - several evaluation improvements
 - time control improvements
 - search improvements
 - multipv implementation improved
 - Better Hash table utilization
 - many others


===================
If you have Windows
===================

The executables for Windows are in the /Windows sub-directory.

You will find 2 versions:

  komodo51r2-64bit.exe
  komodo51r2-32bit.exe


=================
If you have Linux
=================

The binaries for Linux are in the /Linux sub-directory.

You will find 1 version:

  komodo51r2-64bit

===============
If you have OSX
===============

The binaries for OSX are in the /OSX subdirectory.

You will find 1 version:

  komodo51r2-fat


==========
HOW TO RUN
==========

Komodo is a chess engine and not a chess user interface and thus
requires the use of a third party Graphical User Interface as most
modern chess engines do.  The Komodo web site suggests a few Chess
User Interfaces which are available, some of them open source and of
very high quality.

Komodo, like all chess programs, has some user options that will be
explained here.  These can be set or changed from the Graphical
Interface and we will focus on the non-standard ones.

Hash
----
This defines the maximum amount of memory to use for the transposition
table - a major factor in the performance of modern chess programs.
The default is set to 128 which is probably more than adequate for
standard use.  However, see the document setHASH.txt for more specific
information on how this should be set for ultimate performance.


Threads
-------
The default number of threads is 1 so for multi-core machines you will
want to change this value.  For ultimate performance we suggest
setting this to the number of "real" cores on your machine.

For example on an i7 with hyper-threading, you typically have 4 "real"
cores and 4 hyper-threaded or virtual cores.  The operating system will
probably report 8 cores but we recommend setting Komodo for 4 threads
in this case.


Use Lmr
-------
LMR is a search technique that is designed to aggressively prune moves
from the search tree so much deeper depths can be obtained. However
this can sometimes miss important moves.  Komodo gives you the option
to turn this on or off.  In general Komodo will play much stronger
with this option turned on, but one might want to experiment with
turning it off in order to see if a much shallower, but more thorough
search might help in some position.


Null Move pruning
-----------------
Like LMR, this is also a technique to aggressively prune moves from
the search tree.  Komodo plays much stronger with this turned ON, but
occasionally things can be missed, especially very deep threats or
zugzwang positions.  This option allows you to experiment in the case
that you have a difficult position which cannot be resolved and want to
see if a much shallower, but more thorough, search would help.


Move overhead milliseconds
--------------------------
This is designed to compensate for slow user interfaces, where a
fraction of a second can be lost in the processing and transferring of
information back and forth from the engine to the interface.  This
should probably be left alone unless you see the program starting to
forfeit games due to exhausting its time.


Drawscore
---------
In some programs this is called the "contempt factor" and defines the
value of a draw.   The default is -5 which means that the program will
have a slight tendency to avoid a draw, even if its position is slightly
worse. A value of -100 would cause Komodo to avoid a draw unless it was
at least a pawn down. A value of 100 would cause Komodo to seek draws
unless it was at least a pawn ahead.  


time usage aggressiveness
-------------------------
This provides the ability to manipulate Komodo's time control
heuristics, to make it allocation either more aggressively or less
aggressively.  The default is 0 which is what we believe is the ideal
setting but remains to be tested.  You can make it play faster by
using a negative number or you can make it allocate time more
aggressively by setting it to a positive value.  The range of values
is between -9 and +9.  It's very unlikely extreme values will be play
well, so we suggest experimenting with relatively modest changes to
the default.


Minimal Reporting
-----------------
When checked, the engine will not send detailed information on the
progress of the search, basically reverting to only sending principal
variation changes.  This might impact hyper blitz levels where a
slower GUI can be overwhelmelmed by a constant flood of information at
low depths.



Bug fixes and changes in this release
-------------------------------------

 1. Komodo 5.1 did not operate with the book and would crash the
    program when the book was present in the specified path.  Version
    5.1r1 did not fully fix this issue but it is now fixed.

 2. Original 5.1 release had a memory leak which has been fixed since
    version 5.1r1

 3. The Original 5.1 Linux version had an incorrect clock on some
    later Linux distributions due to a library incompatibility.  That
    has been corrected.

 4. Minor evaluation improvements with the very common KRPvsKR
    endings.

 5. Version 5.1r1 would hang up in analysis mode, this has been
    corrected.  

 6. Added a debug style logging feature.   

 7. General stability improvements. 

 8. Fail Hi, Fail Lo reporting.  


