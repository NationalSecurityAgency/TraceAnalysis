use color_eyre::Result;
use crossterm::event::KeyModifiers;
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    layout::{Constraint, Flex, Layout, Margin, Rect},
    style::{self, Color, Modifier, Style, Stylize},
    text::Text,
    widgets::{
        Block, BorderType, Cell, Clear, HighlightSpacing, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, TableState,
    },
    DefaultTerminal, Frame,
};
use style::palette::tailwind;
use unicode_width::UnicodeWidthStr;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;
use trace_tools::api::{TmApi,MemoryInfo,Address,InstructionTick};
use clap::Parser;

const PALETTES: [tailwind::Palette; 4] = [
    tailwind::BLUE,
    tailwind::EMERALD,
    tailwind::INDIGO,
    tailwind::RED,
];
const INFO_TEXT: [&str; 2] = [
    "(Esc) quit | (↑) move up | (↓) move down | (←) move left | (→) move right",
    "(Shift + →) next color | (Shift + ←) previous color",
];

const ITEM_HEIGHT: usize = 1;


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    str_index: String,

    #[arg(long)]
    st_index: String,

    #[arg(long)]
    database_path: String,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();
    let mut api = TmApi::new(args.database_path.clone(), args.st_index.clone(), args.str_index.clone()).unwrap();

    let terminal = ratatui::init();
    let app_result = App::new(api).run(terminal);
    ratatui::restore();
    app_result
}
struct TableColors {
    buffer_bg: Color,
    header_bg: Color,
    header_fg: Color,
    row_fg: Color,
    selected_row_style_fg: Color,
    selected_column_style_fg: Color,
    selected_cell_style_fg: Color,
    normal_row_color: Color,
    alt_row_color: Color,
    footer_border_color: Color,
}

impl TableColors {
    const fn new(color: &tailwind::Palette) -> Self {
        Self {
            buffer_bg: tailwind::SLATE.c950,
            header_bg: color.c900,
            header_fg: tailwind::SLATE.c200,
            row_fg: tailwind::SLATE.c200,
            selected_row_style_fg: color.c400,
            selected_column_style_fg: color.c400,
            selected_cell_style_fg: color.c600,
            normal_row_color: tailwind::SLATE.c950,
            alt_row_color: tailwind::SLATE.c900,
            footer_border_color: color.c400,
        }
    }
}

struct Data {
    addr: u64,
    val: u8,
    addr_str: String,
    val_str: String,
    name: String,
}

impl Data {
    fn new(addr: u64, val : u8, name: String) -> Self {
	Data {
	    addr,
	    val,
	    addr_str: format!("0x{:x}",addr),
	    val_str: format!("0x{:x}",val),
	    name,
	}
    }
    
    const fn ref_array(&self) -> [&String; 3] {
        [&self.addr_str, &self.val_str, &self.name]
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn val(&self) -> &str {
        &self.val_str
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[derive(PartialEq, Debug, Clone)]
enum UiState {
    None,
    GetTick,
    GetAddr,
}

struct App {
    state: TableState,
    ui_state: UiState,
    current_tick: u64,
    current_addr: u64,
    current_meminfo: Option<MemoryInfo>,
    status_msg: String,
    tick_input: Input,
    addr_input: Input,
    items: Vec<Data>,
    longest_item_lens: (u16, u16, u16), // order is (name, address, email)
    scroll_state: ScrollbarState,
    colors: TableColors,
    color_index: usize,
    api: TmApi,
}

impl App {
    fn new(api : TmApi) -> Self {
        let data_vec = vec![Data::new(0xabce as u64, 123 as u8, "foo".to_string()), Data::new(0xabcf as u64, 99 as u8, "bar".to_string())];
        Self {
            state: TableState::default().with_selected(0),
	    ui_state: UiState::None,
	    current_tick: 0 as u64,
	    current_addr: 0 as u64,
	    current_meminfo: None,
	    status_msg: "all good".to_string(),
	    tick_input: Input::default(),
	    addr_input: Input::default(),
            longest_item_lens: constraint_len_calculator(&data_vec),
            scroll_state: ScrollbarState::new((data_vec.len() - 1) * ITEM_HEIGHT),
            colors: TableColors::new(&PALETTES[0]),
            color_index: 0,
            items: data_vec,
	    api,
        }
    }
    pub fn next_row(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
        self.scroll_state = self.scroll_state.position(i * ITEM_HEIGHT);
    }

    pub fn previous_row(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
        self.scroll_state = self.scroll_state.position(i * ITEM_HEIGHT);
    }

    pub fn next_column(&mut self) {
        self.state.select_next_column();
    }

    pub fn previous_column(&mut self) {
        self.state.select_previous_column();
    }

    pub fn next_color(&mut self) {
        self.color_index = (self.color_index + 1) % PALETTES.len();
    }

    pub fn previous_color(&mut self) {
        let count = PALETTES.len();
        self.color_index = (self.color_index + count - 1) % count;
    }

    pub fn set_colors(&mut self) {
        self.colors = TableColors::new(&PALETTES[self.color_index]);
    }
    fn get_tick(&mut self) {
	if self.ui_state == UiState::None {
	    self.ui_state = UiState::GetTick;
	}
    }
    fn get_addr(&mut self) {
	if self.ui_state == UiState::None {
	    self.ui_state = UiState::GetAddr;
	}
    }
    fn cancel_popup(&mut self) {
	self.ui_state = UiState::None;
    }
    fn refresh(&mut self) {
	let start = if self.current_addr > 100 {
	    self.current_addr - 100
	} else {
	    0 as u64
	};
	match self.api.get_memory(self.current_tick, start, 200 as usize) {
	    Ok(res) => self.current_meminfo = Some(res),
	    Err(e) => self.status_msg = format!("Error getting memory: {:?}", e),
	}
	self.status_msg = format!("tick: {}, addr: 0x{:x}", self.current_tick, self.current_addr);
	self.redo_data();
    }
    fn redo_data(&mut self) {
	if let Some(meminfo) = &self.current_meminfo {
	    self.items = Vec::new();
	    for i in 0..meminfo.data.len() {
		let val : u8 = meminfo.data[i];
		let addr : u64 = meminfo.addrs[i];
		if meminfo.write_ticks[i] != 0 {
		    self.items.push(Data::new(addr, val, format!("written at {}",meminfo.write_ticks[i])));
		}
	    }
	}
    }
    fn goto_addr(&mut self) {
	let value = self.addr_input.value();
	let value = value.trim();
	if value.starts_with("0x") || value.starts_with("0X") {
            if let Ok(x) = u64::from_str_radix(&value[2..], 16) {
		self.current_addr = x;
		self.refresh();
		self.addr_input.reset();
		self.cancel_popup();
	    }
	} else {
            if let Ok(x) = value.parse::<u64>() {
		self.current_addr = x;
		self.refresh();
		self.addr_input.reset();
		self.cancel_popup();
	    }
	}
    }
    fn goto_tick(&mut self) {
	let value = self.tick_input.value();
	let value = value.trim();
        if let Ok(x) = value.parse::<u64>() {
	    self.current_tick = x;
	    self.tick_input.reset();
	    self.refresh();
	    self.cancel_popup();
	}
    }

    fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        loop {
            terminal.draw(|frame| self.draw(frame))?;

	    let event = event::read()?;
            if let Event::Key(key) = event {
                if key.kind == KeyEventKind::Press {
		    match self.ui_state {
			UiState::None => {
			    let shift_pressed = key.modifiers.contains(KeyModifiers::SHIFT);
			    match key.code {
				KeyCode::Char('q') => return Ok(()),
				KeyCode::Char('j') | KeyCode::Down => self.next_row(),
				KeyCode::Char('k') | KeyCode::Up => self.previous_row(),
				KeyCode::Char('l') | KeyCode::Right if shift_pressed => self.next_color(),
				KeyCode::Char('h') | KeyCode::Left if shift_pressed => {
				    self.previous_color();
				}
				KeyCode::Char('l') | KeyCode::Right => self.next_column(),
				KeyCode::Char('h') | KeyCode::Left => self.previous_column(),
				KeyCode::Char('t') => self.get_tick(),
				KeyCode::Char('a') => self.get_addr(),
				KeyCode::Esc => {
				    self.cancel_popup();
				},
				_ => {}
			    }
			},
			UiState::GetTick => {
			    match key.code {
				KeyCode::Esc => self.cancel_popup(),
				KeyCode::Enter => self.goto_tick(),
				_ => { self.tick_input.handle_event(&event); },
			    }
				
			},
			UiState::GetAddr => {
			    match key.code {
				KeyCode::Esc => self.cancel_popup(),
				KeyCode::Enter => self.goto_addr(),
				_ => { self.addr_input.handle_event(&event); },
			    }
			},
		    }
                }
            }
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let vertical = &Layout::vertical([Constraint::Min(5), Constraint::Length(4)]);
        let area = frame.area();
        let rects = vertical.split(area);

        self.set_colors();

        self.render_table(frame, rects[0]);
        self.render_scrollbar(frame, rects[0]);
        self.render_footer(frame, rects[1]);
	
        match self.ui_state {
	    UiState::GetTick => self.render_tick_input(frame, popup_area(area, 60, 20)),
	    UiState::GetAddr => self.render_addr_input(frame, popup_area(area, 60, 20)),
	    _ => {},
        }
    }
	
    fn render_tick_input(&self, frame: &mut Frame, area: Rect) {
	frame.render_widget(Clear, area);
        let width = area.width.max(3) - 3;
        let scroll = self.tick_input.visual_scroll(width as usize);
        let style : Style = Color::Yellow.into();
        let input = Paragraph::new(self.tick_input.value())
            .style(style)
            .scroll((0, scroll as u16))
            .block(Block::bordered().title("Goto tick"));
        frame.render_widget(input, area);

        let x = self.tick_input.visual_cursor().max(scroll) - scroll + 1;
        frame.set_cursor_position((area.x + x as u16, area.y + 1));
    }

    fn render_addr_input(&self, frame: &mut Frame, area: Rect) {
	frame.render_widget(Clear, area);
        let width = area.width.max(3) - 3;
        let scroll = self.addr_input.visual_scroll(width as usize);
        let style : Style = Color::Yellow.into();
        let input = Paragraph::new(self.addr_input.value())
            .style(style)
            .scroll((0, scroll as u16))
            .block(Block::bordered().title("Goto addr"));
        frame.render_widget(input, area);

        let x = self.addr_input.visual_cursor().max(scroll) - scroll + 1;
        frame.set_cursor_position((area.x + x as u16, area.y + 1));
    }

    fn render_table(&mut self, frame: &mut Frame, area: Rect) {
        let header_style = Style::default()
            .fg(self.colors.header_fg)
            .bg(self.colors.header_bg);
        let selected_row_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.colors.selected_row_style_fg);
        let selected_col_style = Style::default().fg(self.colors.selected_column_style_fg);
        let selected_cell_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.colors.selected_cell_style_fg);

        let header = ["Address", "Value", "Name"]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(header_style)
            .height(1);
        let rows = self.items.iter().enumerate().map(|(i, data)| {
            let color = match i % 2 {
                0 => self.colors.normal_row_color,
                _ => self.colors.alt_row_color,
            };
            let item = data.ref_array();
            item.into_iter()
                .map(|content| Cell::from(Text::from(format!("{content}\n"))))
                .collect::<Row>()
                .style(Style::new().fg(self.colors.row_fg).bg(color))
                .height(ITEM_HEIGHT as u16)
        });
        let bar = " █ ";
        let t = Table::new(
            rows,
            [
                // + 1 is for padding.
                Constraint::Length(self.longest_item_lens.0 + 1),
                Constraint::Min(self.longest_item_lens.1 + 1),
                Constraint::Min(self.longest_item_lens.2),
            ],
        )
        .header(header)
        .row_highlight_style(selected_row_style)
        .column_highlight_style(selected_col_style)
        .cell_highlight_style(selected_cell_style)
        .highlight_symbol(Text::from(vec![
            "".into(),
            bar.into(),
            bar.into(),
            "".into(),
        ]))
        .bg(self.colors.buffer_bg)
        .highlight_spacing(HighlightSpacing::Always);
        frame.render_stateful_widget(t, area, &mut self.state);
    }

    fn render_scrollbar(&mut self, frame: &mut Frame, area: Rect) {
        frame.render_stateful_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None),
            area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }),
            &mut self.scroll_state,
        );
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let info_footer = Paragraph::new(self.status_msg.clone())
            .style(
                Style::new()
                    .fg(self.colors.row_fg)
                    .bg(self.colors.buffer_bg),
            )
            .centered()
            .block(
                Block::bordered()
                    .border_type(BorderType::Double)
                    .border_style(Style::new().fg(self.colors.footer_border_color)),
            );
        frame.render_widget(info_footer, area);
    }
}

fn constraint_len_calculator(items: &[Data]) -> (u16, u16, u16) {
    let name_len = items
        .iter()
        .map(Data::name)
        .map(UnicodeWidthStr::width)
        .max()
        .unwrap_or(0);
    let addr_len = items
        .iter()
        .map(Data::addr)
        .flat_map(str::lines)
        .map(UnicodeWidthStr::width)
        .max()
        .unwrap_or(0);
    let val_len = items
        .iter()
        .map(Data::val)
        .map(UnicodeWidthStr::width)
        .max()
        .unwrap_or(0);

    #[allow(clippy::cast_possible_truncation)]
    (30 as u16, val_len as u16, name_len as u16)
}

    fn popup_area(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
	let vertical = Layout::vertical([Constraint::Percentage(percent_y)]).flex(Flex::Center);
	let horizontal = Layout::horizontal([Constraint::Percentage(percent_x)]).flex(Flex::Center);
	let [area] = vertical.areas(area);
	let [area] = horizontal.areas(area);
	area
    }
