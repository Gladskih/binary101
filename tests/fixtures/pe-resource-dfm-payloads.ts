// Inno notebook pages fill their parent and only the saved ActivePage is visible.
// https://github.com/jrsoftware/issrc/blob/main/Components/NewNotebook.pas
export const createNotebookDfmResource = (): string => `object NotebookPreview: TForm
  Left = 100
  Top = 200
  ClientWidth = 400
  ClientHeight = 240
  Font.Name = 'Tahoma'
  Font.Height = -11
  object Pages: TNewNotebook
    Left = 4
    Top = 64
    Width = 389
    Height = 170
    ActivePage = Installing
    object Installing: TNewNotebookPage
      object Progress: TNewProgressBar
        Left = 36
        Top = 56
        Width = 317
        Height = 21
        Min = 100
        Max = 400
        Position = 250
      end
      object Status: TNewStaticText
        Caption = '*'
        Width = 317
        Height = 16
      end
    end
    object Other: TNewNotebookPage
      object HiddenText: TLabel
        Caption = 'Inactive page'
      end
    end
  end
  object HiddenLabel: TNewStaticText
    Visible = False
    Caption = 'Hidden'
  end
end`;
