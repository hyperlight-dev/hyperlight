use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::Duration;

use piet_common::{kurbo, Color, RenderContext, Text, TextLayout, TextLayoutBuilder};

fn read_u128(inf: &mut File) -> Result<u128, std::io::Error> {
    let mut bytes: [u8; 16] = [0; 16];
    inf.read_exact(&mut bytes)?;
    Ok(u128::from_ne_bytes(bytes))
}
fn read_u64(inf: &mut File) -> Option<u64> {
    let mut bytes: [u8; 8] = [0; 8];
    inf.read_exact(&mut bytes).ok()?;
    Some(u64::from_ne_bytes(bytes))
}
fn read_u64_vec(inf: &mut File) -> Option<Vec<u64>> {
    let len = read_u64(inf)?;
    let mut vec = Vec::with_capacity(len as usize);
    for _ in 0..len {
        vec.push(read_u64(inf)?);
    }
    Some(vec)
}
fn read_blake3_hash(inf: &mut File) -> Option<blake3::Hash> {
    let mut bytes: [u8; 32] = [0; 32];
    inf.read_exact(&mut bytes).ok()?;
    Some(blake3::Hash::from_bytes(bytes))
}

fn dump_stack(state: &mut State, trace: Rc<[u64]>) {
    for frame in &*trace {
        println!("  {:x} {}", frame, state.symbol_cache.format_symbol(*frame));
    }
}

fn dump_ident(_state: &mut State, _rs: &mut (), now: Duration, hash: blake3::Hash) -> Option<()> {
    println!("\n[{:9?}] BLAKE3 hash of binary is {}", now, hash);
    Some(())
}

fn dump_unwind(state: &mut State, _rs: &mut (), now: Duration, trace: Rc<[u64]>) -> Option<()> {
    println!("\n[{:9?}] Guest requested stack trace", now);
    dump_stack(state, trace);
    Some(())
}

fn dump_alloc(
    state: &mut State,
    _rs: &mut (),
    now: Duration,
    ptr: u64,
    amt: u64,
    trace: Rc<[u64]>,
) -> Option<()> {
    println!("\n[{:9?}] Allocated {} bytes at 0x{:x}", now, amt, ptr);
    dump_stack(state, trace);
    Some(())
}

fn dump_free(
    state: &mut State,
    _rs: &mut (),
    now: Duration,
    ptr: u64,
    amt: u64,
    trace: Rc<[u64]>,
) -> Option<()> {
    println!("\n[{:9?}] Freed {} bytes at 0x{:x}", now, amt, ptr);
    dump_stack(state, trace);
    Some(())
}

// todo: this should use something more reasonable than a hash table
// for each node. let's measure the out-degree and see if a small
// array is better, to start.
struct TraceTrie<T> {
    value: T,
    children: HashMap<u64, TraceTrie<T>>,
}
impl<T: Default> TraceTrie<T> {
    fn new() -> Self {
        Self {
            value: Default::default(),
            children: HashMap::new(),
        }
    }
    fn apply_path<'a, 'i, F: Fn(&mut T), I: Iterator<Item = &'i u64>>(
        &'a mut self,
        trace: I,
        f: F,
    ) {
        let mut node = self;
        for frame in trace {
            f(&mut node.value);
            node = (*node).children.entry(*frame).or_insert(Self::new())
        }
        f(&mut node.value);
    }
}

struct SymbolCache {
    loader: addr2line::Loader,
    symbol_cache: HashMap<u64, Option<(String, Option<u32>)>>,
}
impl SymbolCache {
    fn resolve_symbol<'c>(&'c mut self, addr: u64) -> &'c Option<(String, Option<u32>)> {
        self.symbol_cache.entry(addr).or_insert_with(|| {
            let frame = &self.loader.find_frames(addr).ok()?.next().ok()??;
            let function = frame.function.as_ref()?;
            let demangled =
                addr2line::demangle_auto(function.name.to_string_lossy(), function.language)
                    .to_string();
            Some((demangled, frame.location.as_ref()?.line))
        })
    }
    fn format_symbol(&mut self, addr: u64) -> String {
        match self.resolve_symbol(addr) {
            None => format!("{}", addr),
            Some((f, None)) => f.clone(),
            Some((f, Some(l))) => format!("{}:{}", f, l),
        }
    }
}

enum Visualisation {
    Bar,
    Flame,
}
impl std::fmt::Display for Visualisation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Visualisation::Bar => write!(f, "bar"),
            Visualisation::Flame => write!(f, "flame"),
        }
    }
}

struct State {
    inf: File,
    symbol_cache: SymbolCache,
    out_dir: Option<PathBuf>,
    start_time: Option<Duration>,
    end_time: Option<Duration>,
    allocs: HashMap<u64, (u64, Rc<[u64]>)>,
    sites: HashMap<u64, u64>,
    traces: TraceTrie<u64>,
    total: u64,
    max_total: u64,
    max_duration: Duration,
    num_durations: u64,
}

struct ViewParams<R: piet_common::RenderContext> {
    margin: f64,
    width: f64,
    height: f64,
    label_gap: f64,
    amount_gap: f64,
    bar_start: f64,
    bar_height: f64,
    bar_leading: f64,
    bar_brush: R::Brush,
}

fn draw_bg<R: piet_common::RenderContext>(render_context: &mut R, v: &ViewParams<R>) {
    let bg_brush = render_context.solid_brush(Color::rgb8(255, 255, 255));
    render_context.fill(
        kurbo::Rect {
            x0: 0.0,
            y0: 0.0,
            x1: v.width + v.margin * 2.0,
            y1: v.height + v.margin * 2.0,
        },
        &bg_brush,
    );
}
fn draw_bar<R: piet_common::RenderContext>(
    render_context: &mut R,
    v: &ViewParams<R>,
    stroke: bool,
    n: u64,
    label: String,
    value: u64,
    max_value: u64,
) -> Option<()> {
    let left = v.margin + v.bar_start;
    let top = v.margin + (n as f64) * (v.bar_height + v.bar_leading);
    if stroke {
        render_context.stroke(
            kurbo::Rect {
                x0: left,
                y0: top,
                //x1: v.margin + v.width,
                x1: left + (v.width - v.bar_start),
                y1: top + v.bar_height,
            },
            &v.bar_brush,
            1.0,
        );
    }
    let right = left + (v.width - v.bar_start) * value as f64 / max_value as f64;
    render_context.fill(
        kurbo::Rect {
            x0: left,
            y0: top,
            x1: right,
            y1: top + v.bar_height,
        },
        &v.bar_brush,
    );
    let layout = render_context.text().new_text_layout(label).build().ok()?;
    let metric = layout
        .line_metric(0)
        .expect("there must be at least one line metric");
    render_context.draw_text(
        &layout,
        kurbo::Point {
            x: left - v.label_gap - layout.trailing_whitespace_width(),
            y: top - metric.y_offset + (v.bar_height - metric.baseline) / 2.0,
        },
    );
    let layout = render_context
        .text()
        .new_text_layout(format!("{}", value))
        .default_attribute(piet_common::TextAttribute::TextColor(Color::rgb8(
            255, 255, 255,
        )))
        .build()
        .ok()?;
    let metric = layout
        .line_metric(0)
        .expect("there must be at least one line metric");
    if right - left > v.amount_gap + layout.trailing_whitespace_width() {
        render_context.draw_text(
            &layout,
            kurbo::Point {
                x: right - v.amount_gap - layout.trailing_whitespace_width(),
                y: top + (v.bar_height - metric.height) / 2.0,
            },
        );
    } else {
        // hopefully the choice of colour doesn't affect the layout much
        let layout = render_context
            .text()
            .new_text_layout(format!("{}", value))
            .build()
            .ok()?;
        let metric = layout
            .line_metric(0)
            .expect("there must be at least one line metric");
        render_context.draw_text(
            &layout,
            kurbo::Point {
                x: right + v.amount_gap,
                y: top + (v.bar_height - metric.height) / 2.0,
            },
        );
    }
    Some(())
}

trait RenderWrapper {
    fn render<R: RenderContext>(&mut self, ctx: &mut R, width: u64, height: u64) -> Option<()>;
}
fn render_bitmap<F: RenderWrapper, O: Write>(
    mut out: O,
    device: &mut piet_common::Device,
    mut render: F,
) -> Option<()> {
    let width = 1920;
    let height = 1080;
    let mut bitmap = device.bitmap_target(width, height, 1.0).ok()?;
    {
        let mut render_context = bitmap.render_context();
        render.render(&mut render_context, width as u64, height as u64)?;
        render_context.finish().ok()?;
    }
    out.write_all(
        bitmap
            .to_image_buf(piet_common::ImageFormat::RgbaPremul)
            .expect("unable to access image buffer")
            .raw_pixels(),
    )
    .expect("write to stdout");
    Some(())
}

impl<R: RenderContext> ViewParams<R> {
    fn new(ctx: &mut R, ht: u64, wd: u64) -> Self {
        let margin = 20.0;
        let width = wd as f64 - margin * 2.0;
        let height = ht as f64 - margin * 2.0;
        let bar_brush = ctx.solid_brush(Color::rgb8(128, 0, 128));
        Self {
            margin,
            width,
            height,
            label_gap: 10.0,
            amount_gap: 5.0,
            bar_start: width / 4.0,
            bar_height: 12.0,
            bar_leading: 4.0,
            bar_brush: bar_brush,
        }
    }
}

struct BarRenderer<'r> {
    state: &'r mut State,
    now: Duration,
}
impl<'r, 'a, 's> RenderWrapper for BarRenderer<'r> {
    fn render<R: RenderContext>(&mut self, ctx: &mut R, wd: u64, ht: u64) -> Option<()> {
        let v = ViewParams::new(ctx, ht, wd);
        draw_bg(ctx, &v);
        draw_bar(
            ctx,
            &v,
            true,
            0,
            "Execution time".to_string(),
            self.now.as_micros() as u64,
            self.state.max_duration.as_micros() as u64,
        )?;
        draw_bar(
            ctx,
            &v,
            true,
            1,
            "Total memory consumption".to_string(),
            self.state.total,
            self.state.max_total,
        )?;

        let mut points: Vec<(&u64, &u64)> = self.state.sites.iter().collect();
        points.sort_by_key(|(_, size)| *size);
        for (i, (site, size)) in points.iter().rev().enumerate() {
            draw_bar(
                ctx,
                &v,
                false,
                (3 + i) as u64,
                (&mut self.state.symbol_cache).format_symbol(**site),
                **size,
                self.state.total,
            )?;
        }
        Some(())
    }
}

struct FlameRenderer<'r> {
    state: &'r mut State,
    now: Duration,
}
#[derive(Clone, Copy)]
struct FlameView {
    total_allocated: u64,
    bottom: f64,
    left: f64,
    color: u8,
}
fn draw_flame<R: RenderContext>(
    ctx: &mut R,
    v: &ViewParams<R>,
    fv: &FlameView,
    sc: &mut SymbolCache,
    t: &TraceTrie<u64>,
    addr: Option<u64>,
) -> Option<()> {
    let rect = kurbo::Rect {
        x0: v.margin + fv.left,
        y0: v.margin + fv.bottom - v.bar_height,
        x1: v.margin + fv.left + (t.value as f64) * v.width / (fv.total_allocated as f64),
        y1: v.margin + fv.bottom,
    };
    ctx.fill(rect, &Color::rgb8(255, 0, fv.color));
    if let Some(addr) = addr {
        ctx.save().ok()?;
        ctx.clip(rect);
        let layout = ctx
            .text()
            .new_text_layout(sc.format_symbol(addr))
            .default_attribute(piet_common::TextAttribute::FontSize(9.0))
            .build()
            .ok()?;
        ctx.draw_text(
            &layout,
            kurbo::Point {
                x: v.margin + fv.left,
                y: v.margin + fv.bottom - v.bar_height,
            },
        );
        ctx.restore().ok()?;
    }
    let mut child_fv = FlameView {
        total_allocated: fv.total_allocated,
        bottom: fv.bottom - v.bar_height,
        left: fv.left,
        color: fv.color,
    };
    for (addr, child) in &t.children {
        draw_flame(ctx, v, &child_fv, sc, child, Some(*addr))?;
        child_fv.left += (child.value as f64) * v.width / (fv.total_allocated as f64);
        child_fv.color = child_fv.color.wrapping_add(85);
    }
    Some(())
}
impl<'r, 'a, 's> RenderWrapper for FlameRenderer<'r> {
    fn render<R: RenderContext>(&mut self, ctx: &mut R, wd: u64, ht: u64) -> Option<()> {
        let mut v = ViewParams::new(ctx, ht, wd);
        v.bar_start = v.width / 8.0;
        draw_bg(ctx, &v);
        draw_bar(
            ctx,
            &v,
            true,
            0,
            "Execution time".to_string(),
            self.now.as_micros() as u64,
            self.state.max_duration.as_micros() as u64,
        )?;
        draw_bar(
            ctx,
            &v,
            true,
            1,
            "Total memory consumption".to_string(),
            self.state.total,
            self.state.max_total,
        )?;

        let fv = FlameView {
            total_allocated: self.state.total,
            bottom: v.height,
            left: 0.0,
            color: 0,
        };
        draw_flame(
            ctx,
            &v,
            &fv,
            &mut self.state.symbol_cache,
            &self.state.traces,
            None,
        )?;
        Some(())
    }
}

struct RenderState<'a> {
    device: &'a mut piet_common::Device,
    bar_out: std::process::ChildStdin,
    flame_out: std::process::ChildStdin,
}
fn render_state(state: &mut State, rs: &mut RenderState, now: Duration) -> Option<()> {
    let late_enough = state.start_time.map(|t| now >= t).unwrap_or(true);
    let early_enough = state.end_time.map(|t| now <= t).unwrap_or(true);
    if late_enough && early_enough {
        render_bitmap(&mut rs.bar_out, rs.device, BarRenderer { state, now })?;
        render_bitmap(&mut rs.flame_out, rs.device, FlameRenderer { state, now })?;
    }
    Some(())
}

fn render_ident(
    _state: &mut State,
    _rs: &mut RenderState,
    _now: Duration,
    _hash: blake3::Hash,
) -> Option<()> {
    Some(())
}

fn render_unwind(
    _state: &mut State,
    _rs: &mut RenderState,
    _now: Duration,
    _trace: Rc<[u64]>,
) -> Option<()> {
    Some(())
}

fn render_alloc(
    state: &mut State,
    rs: &mut RenderState,
    now: Duration,
    _ptr: u64,
    amt: u64,
    trace: Rc<[u64]>,
) -> Option<()> {
    for frame in trace.as_ref() {
        *state.sites.entry(*frame).or_insert(0) += amt;
    }
    state.traces.apply_path(trace.iter().rev(), |t| *t += amt);
    render_state(state, rs, now)?;
    Some(())
}

fn render_free(
    state: &mut State,
    rs: &mut RenderState,
    now: Duration,
    ptr: u64,
    _amt: u64,
    _trace: Rc<[u64]>,
) -> Option<()> {
    let (amt, trace) = state
        .allocs
        .get(&ptr)
        .expect("free of un-allocated address");
    for frame in trace.as_ref() {
        *state
            .sites
            .get_mut(frame)
            .expect("free of un-allocated site") -= amt;
    }
    state.traces.apply_path(trace.iter().rev(), |t| *t -= amt);
    render_state(state, rs, now)?;
    Some(())
}

fn read_file<I, U, A, F, S>(
    state: &mut State,
    mut handle_state: S,
    handle_ident: I,
    handle_unwind: U,
    handle_alloc: A,
    handle_free: F,
) -> Option<()>
where
    I: Fn(&mut State, &mut S, Duration, blake3::Hash) -> Option<()>,
    U: Fn(&mut State, &mut S, Duration, Rc<[u64]>) -> Option<()>,
    A: Fn(&mut State, &mut S, Duration, u64, u64, Rc<[u64]>) -> Option<()>,
    F: Fn(&mut State, &mut S, Duration, u64, u64, Rc<[u64]>) -> Option<()>,
{
    loop {
        let time = match read_u128(&mut state.inf) {
            Ok(t) => t,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                } else {
                    return None;
                }
            }
        };
        let now = Duration::from_micros(time.try_into().expect("duration too large for u64"));
        state.max_duration = std::cmp::max(state.max_duration, now);
        state.num_durations += 1;

        let frame_id = read_u64(&mut state.inf)?;

        if frame_id == 0 {
            let hash = read_blake3_hash(&mut state.inf)?;
            handle_ident(state, &mut handle_state, now, hash)?;
        } else if frame_id == 1 {
            let trace: Rc<[u64]> = read_u64_vec(&mut state.inf)?.into();
            handle_unwind(state, &mut handle_state, now, trace)?;
        } else if frame_id == 2 {
            let ptr = read_u64(&mut state.inf)?;
            let amt = read_u64(&mut state.inf)?;
            let trace: Rc<[u64]> = read_u64_vec(&mut state.inf)?.into();
            state.allocs.insert(ptr, (amt, trace.clone()));
            state.total += amt;
            if state.total > state.max_total {
                state.max_total = state.total;
            }
            handle_alloc(state, &mut handle_state, now, ptr, amt, trace)?;
        } else if frame_id == 3 {
            let ptr = read_u64(&mut state.inf)?;
            let _ = read_u64_vec(&mut state.inf)?;
            let amt_trace = state
                .allocs
                .get(&ptr)
                .expect("free of un-allocated address");
            let amt = amt_trace.0;
            let trace = amt_trace.1.clone();
            state.total -= amt;
            handle_free(state, &mut handle_state, now, ptr, amt, trace)?;
        } else {
            return None;
        }
    }
    Some(())
}

fn mkv_for(out_dir: &PathBuf, vis: Visualisation, start: Duration) -> PathBuf {
    out_dir.join(format!("{:08}.{}.mkv", start.as_micros(), vis))
}
fn ffmpeg_for(
    out_dir: &PathBuf,
    vis: Visualisation,
    start: Duration,
) -> Option<std::process::Child> {
    let out = std::fs::File::create(out_dir.join(format!("{:08}.{}.out", start.as_micros(), vis)))
        .ok()?;
    let err = std::fs::File::create(out_dir.join(format!("{:08}.{}.err", start.as_micros(), vis)))
        .ok()?;
    let mkv = mkv_for(out_dir, vis, start);
    let _ = std::fs::remove_file(&mkv);
    std::process::Command::new("ffmpeg")
        .args([
            "-f",
            "rawvideo",
            "-pix_fmt",
            "rgba",
            "-framerate",
            "60",
            "-video_size",
            "1920x1080",
            "-i",
            "-",
            "-c:v",
            "libvpx-vp9",
            "-crf",
            "15",
            "-b:v",
            "0",
        ])
        .arg(mkv)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::from(out))
        .stderr(std::process::Stdio::from(err))
        .spawn()
        .ok()
}

fn spawn_render_thread(
    state: &mut State,
    exe_file_name: String,
    in_file_name: String,
    interval: (Duration, Duration),
) -> std::thread::JoinHandle<Option<()>> {
    let out_dir = state.out_dir.clone();
    let max_total = state.max_total;
    let max_duration = state.max_duration;
    std::thread::spawn(move || {
        let out_dir = out_dir?;
        eprintln!(
            "> {:08} -- {:08}",
            interval.0.as_micros(),
            interval.1.as_micros()
        );
        let loader = addr2line::Loader::new(exe_file_name).ok()?;
        let inf = File::open(in_file_name).expect("could not open dump file");
        let mut bar_ffmpeg = ffmpeg_for(&out_dir, Visualisation::Bar, interval.0)?;
        let mut flame_ffmpeg = ffmpeg_for(&out_dir, Visualisation::Flame, interval.0)?;
        let mut job_state = State {
            inf: inf,
            symbol_cache: SymbolCache {
                loader,
                symbol_cache: HashMap::new(),
            },
            start_time: Some(interval.0),
            end_time: Some(interval.1),
            out_dir: Some(out_dir),
            allocs: HashMap::new(),
            sites: HashMap::new(),
            traces: TraceTrie::new(),
            total: 0,
            max_total,
            max_duration,
            num_durations: 0,
        };
        /* plot each individual frame */
        let mut device = piet_common::Device::new().expect("could not create Piet device");
        let rs = RenderState {
            device: &mut device,
            bar_out: bar_ffmpeg.stdin.take().expect("bar ffmpeg stdin"),
            flame_out: flame_ffmpeg.stdin.take().expect("flame ffmpeg stdin"),
        };
        read_file(
            &mut job_state,
            rs,
            render_ident,
            render_unwind,
            render_alloc,
            render_free,
        )?;
        bar_ffmpeg.wait().ok()?;
        flame_ffmpeg.wait().ok()?;
        Some(())
    })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let is_list = args.len() == 4 && args[3] == "list_frames";
    let is_plot = args.len() == 6 && args[3] == "plot_mem";
    if !is_list && !is_plot {
        eprintln!("usage: {} <guest bin> <trace file> list_frames", args[0]);
        eprintln!(
            "usage: {} <guest bin> <trace file> plot_mem <out dir> <jobs>",
            args[0]
        );
        return;
    }
    let Ok(loader) = addr2line::Loader::new(&args[1]) else {
        eprintln!("could not load guest binary {}", args[1]);
        return;
    };
    let inf = File::open(args[2].clone()).expect("could not open trace file");
    let state = State {
        inf: inf,
        symbol_cache: SymbolCache {
            loader: loader,
            symbol_cache: HashMap::new(),
        },
        start_time: None,
        end_time: None,
        out_dir: None,
        allocs: HashMap::new(),
        sites: HashMap::new(),
        traces: TraceTrie::new(),
        total: 0,
        max_total: 0,
        max_duration: Duration::ZERO,
        num_durations: 0,
    };
    if is_list {
        dump_trace(state);
    } else if is_plot {
        plot_mem(args, state);
    }
}

fn dump_trace(mut state: State) {
    read_file(
        &mut state,
        (),
        dump_ident,
        dump_unwind,
        dump_alloc,
        dump_free,
    );
}

fn plot_mem(args: Vec<String>, mut state: State) {
    let out_dir = PathBuf::from(args[4].clone());
    state.out_dir = Some(out_dir.clone());
    std::fs::create_dir_all(&out_dir).expect("could not create output dir");

    /* first pass: compute the maximum memory usage */
    match read_file(
        &mut state,
        (),
        |_, _, _, _| Some(()),
        |_, _, _, _| Some(()),
        |_, _, _, _, _, _| Some(()),
        |_, _, _, _, _, _| Some(()),
    ) {
        Some(()) => (),
        None => {
            eprintln!("i/o error encountered");
            ()
        }
    }
    eprintln!("max total memory used is {}", state.max_total);
    state
        .inf
        .seek(SeekFrom::Start(0))
        .expect("couldn't seek back");
    state.allocs = HashMap::new();
    state.total = 0;

    /* second pass: compute fair durations so that each parallel job
     * processes the same number of frames */
    let num_segments = str::parse::<u64>(&args[5]).expect("number of segments must be a number");
    let durations_per_segment = (state.num_durations - 1) / num_segments + 1;
    state.num_durations = 0;
    let jobs = Mutex::new(Vec::new());
    let start_duration = Mutex::new(Duration::ZERO);
    let count_frame = |s: &mut State, _: &mut (), n: Duration, _, _, _| {
        if s.num_durations == 1 {
            *start_duration.lock().unwrap() = n;
        }
        if s.num_durations == durations_per_segment {
            (*jobs.lock().unwrap()).push((*start_duration.lock().unwrap(), n));
            s.num_durations = 0;
        }
        Some(())
    };
    read_file(
        &mut state,
        (),
        |_, _, _, _| Some(()),
        |_, _, _, _| Some(()),
        count_frame,
        count_frame,
    );
    if state.num_durations > 0 {
        (*jobs.lock().unwrap()).push((*start_duration.lock().unwrap(), state.max_duration));
    }

    /* third pass: render in parallel */
    let mut handles = Vec::new();
    for job in &*jobs.lock().unwrap() {
        handles.push(spawn_render_thread(
            &mut state,
            args[1].clone(),
            args[2].clone(),
            *job,
        ));
    }
    for handle in handles {
        handle.join().expect("thread died");
    }

    /* merge all the parallel rendered segments */
    let mut merge_bar = std::process::Command::new("mkvmerge");
    merge_bar.arg("-o").arg(out_dir.join("bar.mkv"));
    let mut merge_flame = std::process::Command::new("mkvmerge");
    merge_flame.arg("-o").arg(out_dir.join("flame.mkv"));
    for (n, job) in (*jobs.lock().unwrap()).iter().enumerate() {
        if n > 0 {
            merge_bar.arg("+");
            merge_flame.arg("+");
        }
        merge_bar.arg(mkv_for(&out_dir, Visualisation::Bar, job.0));
        merge_flame.arg(mkv_for(&out_dir, Visualisation::Flame, job.0));
    }
    merge_bar.status().unwrap();
    merge_flame.status().unwrap();
}
