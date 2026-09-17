# Building a standalone Cheat Wizard trainer

## 1. Produce stable pointer profiles

In `cw-gui.exe`, find the target value, run pointer discovery, restart/rescan until the desired chains are stable, then save a `.cwptr` profile from the Pointers workspace.

Repeat for each logical value the trainer should expose. New profiles use the `CWPROF01` format; compatible legacy `.mcptr` / `MCEPROF1` profiles can still be loaded and packaged.

## 2. Create the trainer project

Open the **Trainer** workspace in `cw-gui.exe`.

- Add saved `.cwptr` profiles (legacy `.mcptr` is accepted when importing old work).
- Edit labels and optional default values.
- Configure whether the current value, editing and Freeze controls are available.
- Add ordered title/subtitle blocks as needed.
- Open **Visual** to choose theme colors and an optional `.ico`; an image can also be converted to a multi-size ICO directly in the GUI.
- Check the live preview and save a `.cwtrainer` project.

The GUI creates configuration only; it does not invoke the builder. This keeps the engineering UI and packaging responsibilities separate.

## 3. Generate the single EXE

From a terminal:

```bat
cw-trainer-builder.exe build trainer.cwtrainer -o MyTrainer.exe
```

The builder validates referenced profiles and visual settings, optionally writes the selected `.ico` into the PE resources, embeds the visual theme and profiles, and creates one standalone executable.

The legacy shorthand remains accepted:

```bat
cw-trainer-builder.exe trainer.cwtrainer -o MyTrainer.exe
```

## 4. Distribution

Distribute only the generated trainer when that is all the recipient needs:

```text
MyTrainer.exe
```

The generated trainer does not need `cw.exe`, `cw-gui.exe`, `cw-trainer-builder.exe`, JSON, external `.cwptr` files, Python or the Visual C++ Redistributable from the portable no-CRT build.

## Runtime behavior

If the configured process is not running, the trainer waits for it. When the executable appears, the trainer attaches and resolves the embedded pointer profiles. If the process closes and starts again, the trainer resolves module bases and chains against the new PID.

New `.cwtrainer` projects use `"format": "cheat-wizard-trainer"` version 1. `cw-trainer-builder.exe` also accepts legacy JSON projects using `"format": "minice-trainer"` version 1.
